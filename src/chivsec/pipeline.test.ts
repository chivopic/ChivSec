import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { getFixture } from "./fixtures.ts";
import { runPipeline } from "./pipeline.ts";

function fixture(id: string) {
  const repo = getFixture(id);
  assert.ok(repo, id);
  return repo;
}

describe("chivsec v0.1 pipeline", () => {
  it("confirms IDOR on tiny-notes update and rejects the guarded get", () => {
    const report = runPipeline(fixture("tiny-notes"));
    const update = report.findings.find((f) => f.attackPath.entry.includes("PUT"));
    const get = report.findings.find((f) => f.attackPath.entry.includes("GET"));
    const del = report.findings.find((f) => f.attackPath.entry.includes("DELETE"));
    assert.equal(update?.status, "confirmed");
    assert.equal(update?.evidence.dynamic[0]?.result, "invariant_violated");
    assert.equal(get?.status, "rejected");
    assert.equal(del?.status, "rejected");
    assert.ok(report.cost.llmCalls === 0);
  });

  it("holds the authorization invariant after the fix", () => {
    const report = runPipeline(fixture("tiny-notes-fixed"));
    const update = report.findings.find((f) => f.attackPath.entry.includes("PUT"));
    assert.equal(update?.status, "rejected");
    assert.equal(update?.evidence.dynamic[0]?.result, "invariant_held");
    assert.equal(report.summary.confirmed, 0);
  });

  it("confirms command injection on tiny-shell", () => {
    const report = runPipeline(fixture("tiny-shell"));
    const backup = report.findings.find((f) => f.family === "injection_sink");
    assert.equal(backup?.status, "confirmed");
    assert.match(backup?.evidence.dynamic[0]?.observation ?? "", /exec\(\) received/);
  });

  it("rejects the safe execFile backup", () => {
    const report = runPipeline(fixture("tiny-shell-safe"));
    const backup = report.findings.find((f) => f.family === "injection_sink");
    assert.equal(backup?.status, "rejected");
  });

  it("does not treat Semgrep as the case opener — hypotheses come from invariants", () => {
    const report = runPipeline(fixture("tiny-notes"));
    assert.ok(report.invariants.some((i) => i.id === "inv.authz.resource_owner"));
    assert.ok(report.hypotheses.every((h) => h.invariantId.startsWith("inv.")));
  });
});
