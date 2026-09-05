import { loadSlice } from "../sandbox.ts";
import type { DynamicEvidence, SecurityHandoff, VirtualRepo } from "../types.ts";

const PROBE = ";id;#";

export function validateInjection(repo: VirtualRepo, handoff: SecurityHandoff): DynamicEvidence {
  const file = repo.files.find((f) => f.path.endsWith(".js")) ?? repo.files[0];
  if (!file) {
    return {
      validator: "injection.v1",
      result: "error",
      observation: "No JavaScript file in the slice.",
      harness: "injection.exec-probe",
      setup: {},
    };
  }

  try {
    const loaded = loadSlice(file.content);
    const handler = loaded.exports[handoff.validationPlan.slice];
    if (typeof handler !== "function") {
      return {
        validator: "injection.v1",
        result: "inconclusive",
        observation: `Export ${handoff.validationPlan.slice} is not a function.`,
        harness: "injection.exec-probe",
        setup: {},
      };
    }

    const req = {
      user: { id: "user-a" },
      params: { id: PROBE, name: PROBE },
      query: { name: PROBE, host: PROBE },
      body: { name: PROBE, cmd: PROBE },
    };
    const result = (handler as (r: unknown) => { status?: number })(req);
    const status = result?.status ?? 0;

    const shellHit = loaded.execCalls.find((cmd) => cmd.includes(PROBE));
    if (shellHit) {
      return {
        validator: "injection.v1",
        result: "invariant_violated",
        observation: `exec() received a shell string containing the probe: ${JSON.stringify(shellHit)}`,
        harness: "injection.exec-probe",
        setup: { probe: PROBE, status, execCalls: loaded.execCalls },
      };
    }

    const argvHit = loaded.execFileCalls.find((c) =>
      c.args.some((a) => String(a).includes(PROBE)),
    );
    if (argvHit && loaded.execCalls.length === 0) {
      return {
        validator: "injection.v1",
        result: "invariant_held",
        observation:
          "Probe reached execFile argv, not a shell string. Command injection via shell metacharacters is not demonstrated.",
        harness: "injection.exec-probe",
        setup: { probe: PROBE, status, note: JSON.stringify(loaded.execFileCalls) },
      };
    }

    if (loaded.execCalls.length === 0 && loaded.execFileCalls.length === 0) {
      if (status >= 400) {
        return {
          validator: "injection.v1",
          result: "invariant_held",
          observation: `No process execution. Handler rejected the probe with status ${status}.`,
          harness: "injection.exec-probe",
          setup: { probe: PROBE, status },
        };
      }
      return {
        validator: "injection.v1",
        result: "inconclusive",
        observation: "Handler did not call exec/execFile under the probe.",
        harness: "injection.exec-probe",
        setup: { probe: PROBE, status },
      };
    }

    return {
      validator: "injection.v1",
      result: "invariant_held",
      observation: `Process helpers ran but the probe never entered a shell string. exec=${JSON.stringify(loaded.execCalls)} execFile=${JSON.stringify(loaded.execFileCalls)}`,
      harness: "injection.exec-probe",
      setup: { probe: PROBE, status },
    };
  } catch (err) {
    return {
      validator: "injection.v1",
      result: "error",
      observation: err instanceof Error ? err.message : String(err),
      harness: "injection.exec-probe",
      setup: {},
    };
  }
}
