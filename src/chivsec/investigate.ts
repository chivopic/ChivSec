import { functionHasOwnerCheck } from "./understand.ts";
import type { Hypothesis, SecurityHandoff, Understanding } from "./types.ts";

function lines(source: string, start: number, end: number): string {
  return source
    .split("\n")
    .slice(start - 1, end)
    .join("\n");
}

export function investigate(
  understanding: Understanding,
  sourceByPath: Map<string, string>,
  hypotheses: Hypothesis[],
): SecurityHandoff[] {
  return hypotheses.map((hyp) => {
    const fn = understanding.functions.find((f) => f.name === hyp.handler);
    const source = fn ? sourceByPath.get(fn.path) ?? fn.body : "";
    const hasCheck = functionHasOwnerCheck(fn);
    const usesExec = fn ? /\bexec(?:File|Sync)?\s*\(/.test(fn.body) : false;
    const concatenates = fn ? /\bexec(?:Sync)?\s*\([^)]*\+/.test(fn.body) : false;

    const guardsSeen: string[] = [];
    const guardsMissing: string[] = [];
    if (hyp.family === "authorization") {
      if (hasCheck) guardsSeen.push("ownerId compared to user.id");
      else guardsMissing.push("ownerId compared to user.id");
    }
    if (hyp.family === "injection_sink") {
      if (fn && /execFile\s*\(/.test(fn.body) && !concatenates) {
        guardsSeen.push("execFile argv (no shell concatenation)");
      }
      if (fn && /\.test\(/.test(fn.body)) guardsSeen.push("input allowlist");
      if (concatenates) guardsMissing.push("argv-only execution / allowlist");
    }

    const snippet = fn ? lines(source, fn.startLine, fn.endLine) : "";

    return {
      id: `invst-${hyp.id.replace("hyp-", "")}`,
      hypothesisId: hyp.id,
      family: hyp.family,
      invariantId: hyp.invariantId,
      status: "needs_validation",
      hypothesis: hyp.hypothesis,
      attacker: {
        actorId: hyp.family === "authorization" ? "actor.peer" : "actor.user",
        capabilities: ["valid_session", ...hyp.attackerControl],
        preconditions:
          hyp.family === "authorization"
            ? ["attacker knows victim resource id"]
            : ["attacker can set query/body fields"],
      },
      locus: {
        entryPoint: hyp.entryPoint,
        source: hyp.attackerControl[0] ?? "request",
        transformations: [],
        guardsSeen,
        guardsMissing,
        sink:
          hyp.family === "authorization"
            ? "resource write or sensitive read"
            : usesExec
              ? "process execution"
              : "unknown sink",
        relevantCode: fn
          ? [
              {
                path: fn.path,
                startLine: fn.startLine,
                endLine: fn.endLine,
                snippet,
                why: "Handler under investigation",
              },
            ]
          : [],
      },
      discrepancy:
        hyp.family === "authorization"
          ? {
              kind: "check_vs_use",
              left: hasCheck ? "owner check present" : "no owner check",
              right: "lookup by req.params.id",
            }
          : undefined,
      defenses: {
        existing: guardsSeen,
        whyInsufficient: guardsMissing.length
          ? `Missing: ${guardsMissing.join(", ")}`
          : "Guards appear present; validation must still run.",
      },
      validationPlan: {
        validatorFamily: hyp.family,
        slice: hyp.handler,
        setup:
          hyp.family === "authorization"
            ? "user A, resource owned by B"
            : "probe payload in query.name / query.host / body",
        successCriterion:
          hyp.family === "authorization"
            ? "write/read of B's resource succeeds for A"
            : "exec receives a shell string containing the probe",
        failureCriterion:
          hyp.family === "authorization"
            ? "403/404 and no mutation"
            : "exec not called, or called without the probe in a shell string",
      },
      openQuestions: fn ? [] : [`Handler ${hyp.handler} was not found in the index.`],
    };
  });
}
