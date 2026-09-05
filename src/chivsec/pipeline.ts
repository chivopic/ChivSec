import { generateHypotheses } from "./hypothesis.ts";
import { investigate } from "./investigate.ts";
import { findingFromHandoff } from "./promote.ts";
import { compileInvariants, compileThreatModel } from "./threatmodel.ts";
import type { AuditReport, CostLedger, VirtualRepo } from "./types.ts";
import { understandRepo } from "./understand.ts";
import { runValidator } from "./validate/engine.ts";

export function runPipeline(repo: VirtualRepo): AuditReport {
  const started = Date.now();
  const cost: CostLedger = {
    filesRead: repo.files.length,
    bytesIndexed: repo.files.reduce((n, f) => n + f.content.length, 0),
    functionsParsed: 0,
    hypothesesOpened: 0,
    investigationsRun: 0,
    validationsRun: 0,
    llmCalls: 0,
    llmTokens: 0,
    elapsedMs: 0,
  };

  const understanding = understandRepo(repo);
  cost.functionsParsed = understanding.functions.length;

  const threatModel = compileThreatModel(repo, understanding);
  const invariants = compileInvariants(understanding);
  const hypotheses = generateHypotheses(understanding, invariants);
  cost.hypothesesOpened = hypotheses.length;

  const sourceByPath = new Map(repo.files.map((f) => [f.path, f.content] as const));
  const investigations = investigate(understanding, sourceByPath, hypotheses);
  cost.investigationsRun = investigations.length;

  const findings = investigations.map((handoff, i) => {
    const evidence = runValidator(repo, handoff);
    cost.validationsRun += 1;
    const invariant = invariants.find((inv) => inv.id === handoff.invariantId);
    return findingFromHandoff(handoff, invariant, evidence, i + 1);
  });

  cost.elapsedMs = Date.now() - started;

  const summary = {
    confirmed: findings.filter((f) => f.status === "confirmed").length,
    likely: findings.filter((f) => f.status === "likely").length,
    rejected: findings.filter((f) => f.status === "rejected").length,
    blocked: findings.filter((f) => f.status === "blocked").length,
  };

  return {
    repoId: repo.id,
    repoName: repo.name,
    stages: [
      { id: "understand", label: "Understanding repository", detail: `${understanding.functions.length} functions, ${understanding.entryPoints.length} entry points` },
      { id: "threat-model", label: "Building threat model", detail: `${invariants.length} invariants` },
      { id: "hypothesize", label: "Generating security hypotheses", detail: `${hypotheses.length} schema-gated hypotheses` },
      { id: "investigate", label: "Investigating attack paths", detail: `${investigations.length} handoffs` },
      { id: "validate", label: "Validating candidates", detail: `${cost.validationsRun} slice harnesses` },
      { id: "findings", label: "Generating findings", detail: `Confirmed ${summary.confirmed} · Likely ${summary.likely} · Rejected ${summary.rejected}` },
    ],
    understanding,
    threatModel,
    invariants,
    hypotheses,
    investigations,
    findings,
    cost,
    summary,
  };
}

export function reproduceFinding(repo: VirtualRepo, findingId: string) {
  const report = runPipeline(repo);
  const finding = report.findings.find((f) => f.id === findingId);
  if (!finding) {
    return { ok: false as const, error: `Unknown finding ${findingId}` };
  }
  return {
    ok: true as const,
    finding,
    evidence: finding.evidence.dynamic[0] ?? null,
  };
}
