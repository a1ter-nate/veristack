import { getCoreServices, Plugin, type CommandRunContext, type Finding } from "@veristack/plugin";
import { analyzeErrorAndContractGuards } from "./error-and-contract-guards.ts";
import { analyzeLiskovSubtyping } from "./liskov-guards.ts";
import { lintNoComments } from "./no-comments.ts";
import { analyzeStructure } from "./structure.ts";
import { analyzeTests } from "./test-analyzer.ts";

export { analyzeErrorAndContractGuards } from "./error-and-contract-guards.ts";
export { analyzeLiskovSubtyping } from "./liskov-guards.ts";

export { lintNoComments, type CommentHit, type NoCommentsOptions } from "./no-comments.ts";
export { analyzeOracleAndInstructions } from "./oracle-audit.ts";
export { analyzeUniversalAntiSlopProd, analyzeUniversalLandminesTest } from "./oxc-antislop-landmines.ts";
export { analyzeStructure } from "./structure.ts";
export { analyzeTests, type TestAnalysisResult } from "./test-analyzer.ts";
export { analyzeUniversalBendLaws } from "./universal-laws.ts";

function formatFindings(title: string, findings: readonly Finding[], asJson: boolean): string {
  if (asJson) return JSON.stringify({ title, count: findings.length, findings }, null, 2);
  if (findings.length === 0) return `${title}: 0 issues found.`;
  const lines = [`${title}: ${findings.length} issue(s)`];
  for (const f of findings) {
    lines.push(`  - [${f.severity.toUpperCase()}] ${f.rule} ${f.file}:${f.line} — ${f.message}`);
    lines.push(`      Fix: ${f.fix}`);
  }
  return lines.join("\n");
}

function runNoCommentsCommand(ctx: CommandRunContext): number {
  const discover = getCoreServices().discoverRepo;
  if (!discover) throw new Error("Core discoverRepo service is not registered.");
  const findings: Finding[] = [];
  for (const file of discover(ctx.target).files) {
    if (file.language && !file.isStub) findings.push(...lintNoComments(file.rel, file.content, file.language));
  }
  console.log(formatFindings("no-comments", findings, ctx.asJson));
  return ctx.rest.includes("--fail") && findings.length > 0 ? 1 : 0;
}

export const antiSlopPlugin = Plugin.define({
  id: "veristack.plugin.anti-slop",
  setup(ctx) {
    if (!ctx) throw new Error("Plugin context is required.");
    ctx.analyzer.transform((ed) => {
      if (!ed) throw new Error("Analyzer editor is required.");
      ed.add({
        id: "veristack.anti-slop.no-comments",
        phase: "lint",
        run: (runCtx) => {
          const findings: Finding[] = [];
          for (const file of runCtx.repo.files) {
            if (file.language && !file.isStub) findings.push(...lintNoComments(file.rel, file.content, file.language));
          }
          return findings;
        },
      });
      ed.add({
        id: "veristack.anti-slop.structure",
        phase: "lint",
        run: (runCtx) => [
          ...analyzeStructure(runCtx.repo, runCtx.activeLanguages),
          ...analyzeErrorAndContractGuards(runCtx.repo),
          ...analyzeLiskovSubtyping(runCtx.repo),
        ],
      });
      ed.add({
        id: "veristack.anti-slop.tests",
        phase: "test",
        run: (runCtx) => {
          const res = analyzeTests(runCtx.repo);
          return {
            findings: res.findings,
            testInventory: res.inventory,
            pushDownOpportunities: res.pushDownOpportunities,
          };
        },
      });
    });
    ctx.command.transform((ed) => {
      ed.add({
        id: "veristack.cmd.no-comments",
        name: "no-comments",
        usage: "vstack no-comments [dir] [--json] [--fail]",
        run: runNoCommentsCommand,
      });
    });
  },
});

export default antiSlopPlugin;
