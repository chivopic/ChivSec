import type { FunctionInfo, SinkHit, Understanding, VirtualRepo } from "./types.ts";

function lineOf(source: string, index: number): number {
  return source.slice(0, index).split("\n").length;
}

function matchBrace(source: string, openIndex: number): number {
  let depth = 0;
  for (let i = openIndex; i < source.length; i++) {
    const ch = source[i];
    if (ch === "{") depth++;
    else if (ch === "}") {
      depth--;
      if (depth === 0) return i;
    }
  }
  return -1;
}

export function extractFunctions(path: string, source: string): FunctionInfo[] {
  const results: FunctionInfo[] = [];
  const re = /function\s+([A-Za-z_][\w]*)\s*\(([^)]*)\)\s*\{/g;
  let match: RegExpExecArray | null;
  while ((match = re.exec(source))) {
    const open = match.index + match[0].length - 1;
    const close = matchBrace(source, open);
    if (close < 0) continue;
    const startLine = lineOf(source, match.index);
    const endLine = lineOf(source, close);
    const preceding = source.slice(Math.max(0, match.index - 180), match.index);
    const routeMatch = preceding.match(/@route\s+([A-Z]+)\s+(\S+)/);
    results.push({
      name: match[1] ?? "anonymous",
      params: (match[2] ?? "").trim(),
      body: source.slice(match.index, close + 1),
      path,
      startLine,
      endLine,
      route: routeMatch
        ? { method: routeMatch[1] ?? "GET", path: routeMatch[2] ?? "/" }
        : undefined,
    });
  }
  return results;
}

function snippetAt(source: string, index: number): string {
  const lineStart = source.lastIndexOf("\n", index - 1) + 1;
  const lineEnd = source.indexOf("\n", index);
  return source.slice(lineStart, lineEnd === -1 ? undefined : lineEnd).trim();
}

function findSinks(functions: FunctionInfo[], sourceByPath: Map<string, string>): SinkHit[] {
  const hits: SinkHit[] = [];
  for (const fn of functions) {
    const patterns: Array<{ kind: SinkHit["kind"]; re: RegExp }> = [
      { kind: "exec", re: /\bexec(?:File|Sync)?\s*\(/g },
      { kind: "exec", re: /\bspawn(?:Sync)?\s*\(/g },
      { kind: "sql", re: /\.(?:query|raw|execute)\s*\(/g },
      { kind: "eval", re: /\beval\s*\(/g },
    ];
    for (const { kind, re } of patterns) {
      re.lastIndex = 0;
      let m: RegExpExecArray | null;
      while ((m = re.exec(fn.body))) {
        const interpolatesInput =
          /\+|`\$\{/.test(fn.body) &&
          /req\.(query|body|params|headers)|userInput|filename|name|host/.test(fn.body);
        hits.push({
          kind,
          functionName: fn.name,
          path: fn.path,
          line: fn.startLine + lineOf(fn.body, m.index) - 1,
          snippet: snippetAt(fn.body, m.index),
          interpolatesInput,
        });
      }
    }
  }
  void sourceByPath;
  return hits;
}

function looksLikeOwnerCheck(body: string): boolean {
  return (
    /ownerId\s*!==\s*user\.id/.test(body) ||
    /user\.id\s*!==\s*\w+\.ownerId/.test(body) ||
    /authorize\s*\(/.test(body) ||
    /requireOwner/.test(body) ||
    /if\s*\(\s*\w+\.ownerId/.test(body)
  );
}

export function classifyHandlerKind(name: string, method?: string): "read" | "write" | "other" {
  const n = name.toLowerCase();
  const m = (method ?? "").toUpperCase();
  if (["PUT", "POST", "PATCH", "DELETE"].includes(m)) return "write";
  if (/^(update|delete|create|put|remove|write|save)/.test(n)) return "write";
  if (/^(get|list|read|find|fetch|show)/.test(n)) return "read";
  return "other";
}

export function understandRepo(repo: VirtualRepo): Understanding {
  const functions: FunctionInfo[] = [];
  const sourceByPath = new Map<string, string>();
  for (const file of repo.files) {
    sourceByPath.set(file.path, file.content);
    if (!/\.(js|mjs|cjs|ts)$/.test(file.path)) continue;
    functions.push(...extractFunctions(file.path, file.content));
  }

  const authHelpers = functions
    .filter((f) => /auth|currentUser|requireUser|authorize/i.test(f.name))
    .map((f) => f.name);

  const entryPoints = functions
    .filter((f) => f.route || /^(get|update|delete|create|backup|ping)/i.test(f.name))
    .filter((f) => f.name !== "currentUser")
    .map((f) => ({
      id: `ep.${f.name}`,
      method: f.route?.method ?? "GET",
      path: f.route?.path ?? `fn:${f.name}`,
      handler: f.name,
      file: f.path,
      kind: classifyHandlerKind(f.name, f.route?.method),
    }));

  const sensitiveOps = findSinks(functions, sourceByPath);

  const unknowns: string[] = [];
  if (!functions.some((f) => f.route)) {
    unknowns.push("No @route annotations; handlers inferred from function names.");
  }

  for (const ep of entryPoints) {
    const fn = functions.find((f) => f.name === ep.handler);
    if (ep.kind === "write" && fn && !looksLikeOwnerCheck(fn.body) && !/backup|ping|exec/.test(fn.name)) {
      unknowns.push(`${ep.handler} is a write handler with no visible owner check.`);
    }
  }

  return {
    language: "javascript",
    files: repo.files.map((f) => f.path),
    entryPoints,
    functions,
    authHelpers,
    sensitiveOps,
    resources: [{ name: "note", idField: "id", ownerField: "ownerId" }],
    unknowns,
  };
}

export function functionHasOwnerCheck(fn: FunctionInfo | undefined): boolean {
  return fn ? looksLikeOwnerCheck(fn.body) : false;
}
