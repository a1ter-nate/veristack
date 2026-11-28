import { getCoreServices, Plugin, type CommandRunContext } from "@veristack/plugin";
import { auditBoundedRelationalModels } from "./bounded-model-check.ts";
import { auditFormalSync, formatFormalSyncReport } from "./formal-sync.ts";
import { auditLaws, formatLawsReport } from "./laws.ts";

export { auditBoundedRelationalModels, runBoundedRelationalCheck, type BoundedModelCheckResult, type BoundedRelationalModel } from "./bounded-model-check.ts";
export { auditFormalSync, formatFormalSyncReport } from "./formal-sync.ts";
export { auditLaws, formatLawsReport } from "./laws.ts";

function runFormalSyncCommand(ctx: CommandRunContext): number {
  const discover = getCoreServices().discoverRepo;
  if (!discover) throw new Error("Core discoverRepo service is not registered.");
  const findings = auditFormalSync(discover(ctx.target));
  console.log(ctx.asJson ? JSON.stringify({ findings }, null, 2) : formatFormalSyncReport(findings));
  return ctx.rest.includes("--fail") && findings.length > 0 ? 1 : 0;
}

function runLawsCommand(ctx: CommandRunContext): number {
  const discover = getCoreServices().discoverRepo;
  if (!discover) throw new Error("Core discoverRepo service is not registered.");
  const repo = discover(ctx.target);
  const result = auditLaws(repo, { verify: ctx.rest.includes("--verify") });
  const bmc = ctx.rest.includes("--verify") ? auditBoundedRelationalModels(repo.root) : [];
  const allFindings = [...result.findings, ...bmc.flatMap((r) => r.findings)];
  console.log(ctx.asJson ? JSON.stringify({ ...result, boundedModelChecks: bmc, findings: allFindings }, null, 2) : formatLawsReport({ ...result, findings: allFindings }));
  return ctx.rest.includes("--fail") && allFindings.length > 0 ? 1 : 0;
}

export const lawsFormalPlugin = Plugin.define({
  id: "veristack.plugin.laws-formal",
  setup(ctx) {
    ctx.analyzer.transform((ed) => {
      ed.add({
        id: "veristack.laws-formal.audit",
        phase: "lint",
        run: (runCtx) => [
          ...auditFormalSync(runCtx.repo),
          ...auditLaws(runCtx.repo).findings,
          ...auditBoundedRelationalModels(runCtx.repo.root).flatMap((r) => r.findings),
        ],
      });
    });
    ctx.command.transform((ed) => {
      ed.add({
        id: "veristack.cmd.formal-sync",
        name: "formal-sync",
        usage: "vstack formal-sync [dir] [--json] [--fail]",
        run: runFormalSyncCommand,
      });
      ed.add({
        id: "veristack.cmd.laws",
        name: "laws",
        usage: "vstack laws [dir] [--verify] [--json] [--fail]",
        run: runLawsCommand,
      });
    });
  },
});

export default lawsFormalPlugin;
