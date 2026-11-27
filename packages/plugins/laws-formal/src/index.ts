import { getCoreServices, Plugin, type CommandRunContext } from "@veristack/plugin";
import { auditFormalSync, formatFormalSyncReport } from "./formal-sync.ts";
import { auditLaws, formatLawsReport } from "./laws.ts";

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
  const result = auditLaws(discover(ctx.target), { verify: ctx.rest.includes("--verify") });
  console.log(ctx.asJson ? JSON.stringify(result, null, 2) : formatLawsReport(result));
  return ctx.rest.includes("--fail") && result.findings.length > 0 ? 1 : 0;
}

export const lawsFormalPlugin = Plugin.define({
  id: "veristack.plugin.laws-formal",
  setup(ctx) {
    ctx.analyzer.transform((ed) => {
      ed.add({
        id: "veristack.laws-formal.audit",
        phase: "lint",
        run: (runCtx) => [...auditFormalSync(runCtx.repo), ...auditLaws(runCtx.repo).findings],
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
