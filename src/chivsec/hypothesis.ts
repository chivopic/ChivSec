import { functionHasOwnerCheck } from "./understand.ts";
import type { Hypothesis, Invariant, Understanding } from "./types.ts";

function attackerControls(body: string): string[] {
  const controls: string[] = [];
  if (/req\.params/.test(body)) controls.push("req.params");
  if (/req\.query/.test(body)) controls.push("req.query");
  if (/req\.body/.test(body)) controls.push("req.body");
  if (!controls.length) controls.push("request");
  return controls;
}

export function generateHypotheses(understanding: Understanding, invariants: Invariant[]): Hypothesis[] {
  const out: Hypothesis[] = [];
  let n = 1;

  const authz = invariants.find((i) => i.family === "authorization");
  if (authz) {
    const targets = understanding.entryPoints.filter((e) => authz.relatedHandlers.includes(e.handler));
    for (const ep of targets) {
      const fn = understanding.functions.find((f) => f.name === ep.handler);
      if (!fn) continue;
      if (ep.handler === "health") continue;
      const hasCheck = functionHasOwnerCheck(fn);
      out.push({
        id: `hyp-${String(n++).padStart(2, "0")}`,
        family: "authorization",
        invariantId: authz.id,
        hypothesis: hasCheck
          ? `${ep.handler} appears to check ownership — verify the check uses the same object that is returned or mutated.`
          : `${ep.handler} mutates or returns a resource looked up by attacker-controlled id without a visible owner comparison.`,
        entryPoint: `${ep.method} ${ep.path}`,
        handler: ep.handler,
        attackerControl: attackerControls(fn.body),
        disproofPlan:
          "Call the handler as user-a against a resource owned by user-b. Invariant holds if the call is rejected and state is unchanged.",
        file: ep.file,
      });
    }
  }

  const inj = invariants.find((i) => i.family === "injection_sink");
  if (inj) {
    const sinks = understanding.sensitiveOps.filter((s) => s.kind === "exec");
    const seen = new Set<string>();
    for (const sink of sinks) {
      if (seen.has(sink.functionName)) continue;
      seen.add(sink.functionName);
      const fn = understanding.functions.find((f) => f.name === sink.functionName);
      const ep = understanding.entryPoints.find((e) => e.handler === sink.functionName);
      if (!fn) continue;
      out.push({
        id: `hyp-${String(n++).padStart(2, "0")}`,
        family: "injection_sink",
        invariantId: inj.id,
        hypothesis: sink.interpolatesInput
          ? `${sink.functionName} concatenates request data into a process execution sink.`
          : `${sink.functionName} reaches an execution sink; confirm whether request data is constrained to argv.`,
        entryPoint: ep ? `${ep.method} ${ep.path}` : `fn:${sink.functionName}`,
        handler: sink.functionName,
        attackerControl: attackerControls(fn.body),
        disproofPlan:
          "Invoke the handler with a probe payload in query/body. Invariant holds if exec is not called with that payload in a shell string.",
        file: sink.path,
      });
    }
  }

  return out;
}
