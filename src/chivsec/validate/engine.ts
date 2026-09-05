import type { DynamicEvidence, SecurityHandoff, VirtualRepo } from "../types.ts";
import { validateAuthorization } from "./authorization.ts";
import { validateInjection } from "./injection.ts";

export function runValidator(repo: VirtualRepo, handoff: SecurityHandoff): DynamicEvidence {
  if (handoff.family === "authorization") return validateAuthorization(repo, handoff);
  if (handoff.family === "injection_sink") return validateInjection(repo, handoff);
  return {
    validator: "unknown",
    result: "error",
    observation: `No validator for family ${handoff.family}`,
    harness: "none",
    setup: {},
  };
}
