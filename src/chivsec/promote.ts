import type { DynamicEvidence, Finding, FindingStatus, Invariant, SecurityHandoff } from "./types.ts";

function promote(result: DynamicEvidence["result"]): FindingStatus {
  if (result === "invariant_violated") return "confirmed";
  if (result === "invariant_held") return "rejected";
  if (result === "error") return "blocked";
  return "likely";
}

export function findingFromHandoff(
  handoff: SecurityHandoff,
  invariant: Invariant | undefined,
  evidence: DynamicEvidence,
  index: number,
): Finding {
  const status = promote(evidence.result);
  return {
    id: `finding_${String(index).padStart(2, "0")}`,
    status,
    hypothesis: handoff.hypothesis,
    invariantId: handoff.invariantId,
    brokenInvariant: invariant?.statement ?? handoff.invariantId,
    family: handoff.family,
    attackerControl: handoff.attacker.capabilities,
    attackPreconditions: handoff.attacker.preconditions,
    attackPath: {
      entry: handoff.locus.entryPoint,
      steps: [
        `source: ${handoff.locus.source}`,
        ...handoff.locus.guardsSeen.map((g) => `guard seen: ${g}`),
        ...handoff.locus.guardsMissing.map((g) => `guard missing: ${g}`),
        `sink: ${handoff.locus.sink}`,
      ],
      sink: handoff.locus.sink,
    },
    relevantCode: handoff.locus.relevantCode,
    evidence: {
      static: [
        { kind: "guards_seen", detail: handoff.locus.guardsSeen.join("; ") || "none" },
        { kind: "guards_missing", detail: handoff.locus.guardsMissing.join("; ") || "none" },
      ],
      dynamic: [evidence],
    },
    validation: {
      method: "slice_harness",
      reproduction: `chivsec reproduce ${`finding_${String(index).padStart(2, "0")}`}`,
      limitations: ["In-process slice with mocked exec/db. Middleware outside the handler is not loaded."],
    },
    impact: {
      whatAttackerGets:
        status === "confirmed"
          ? handoff.family === "authorization"
            ? "Cross-object read or write of a peer-owned record."
            : "Attacker data enters a shell command string."
          : "None proven.",
      whatIsNotClaimed: "RCE against a production host, authn bypass, or extra-slice middleware flaws.",
    },
    confidence: {
      exploitability: status === "confirmed" ? "high" : status === "rejected" ? "low" : "med",
      evidenceStrength: evidence.result === "error" || evidence.result === "inconclusive" ? "weak" : "dynamic",
    },
    lineage: { handoffId: handoff.id, hypothesisId: handoff.hypothesisId },
  };
}
