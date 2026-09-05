import { getFixture } from "./fixtures.ts";
import { runPipeline } from "./pipeline.ts";

const id = process.argv[2] ?? "tiny-notes";
const repo = getFixture(id);
if (!repo) {
  console.error(`Unknown fixture ${id}. Try: tiny-notes tiny-notes-fixed tiny-shell tiny-shell-safe`);
  process.exit(1);
}

const report = runPipeline(repo);
for (const [i, stage] of report.stages.entries()) {
  console.log(`[${i + 1}/${report.stages.length}] ${stage.label}`);
  console.log(`         ${stage.detail}`);
}
console.log("");
console.log(`Confirmed: ${report.summary.confirmed}`);
console.log(`Likely:    ${report.summary.likely}`);
console.log(`Rejected:  ${report.summary.rejected}`);
console.log("");
for (const finding of report.findings) {
  console.log(`- ${finding.id}  ${finding.status.padEnd(10)}  ${finding.attackPath.entry}`);
}
