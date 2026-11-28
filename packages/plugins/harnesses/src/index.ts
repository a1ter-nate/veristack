import { Plugin, registerCoreServices, type CommandRunContext } from "@veristack/plugin";
import { scanSingleFile } from "./check-file.ts";
import { handleHooksAndDoctorCli } from "./cli-hooks.ts";
import { handleReportCli } from "./report.ts";

export { formatSingleFileReport, scanSingleFile } from "./check-file.ts";
export { handleHooksAndDoctorCli } from "./cli-hooks.ts";
export { formatDoctorReport, runDoctor, type DoctorActionLevel, type DoctorFinding, type DoctorReport } from "./doctor.ts";
export { formatInitReport, initVeristackRepo, type InitRepoOptions, type InitRepoResult } from "./init.ts";
export { buildHookCommand, formatHooksStatus, manageHooks, type HooksAdminAction, type HooksAdminResult } from "./install.ts";
export {
  anonymizeSnippet,
  buildIssueUrl,
  buildToolReport,
  flushLocalFeedbackQueue,
  handleReportCli,
  redactReportText,
  type FlushQueueGroup,
  type FlushQueueOptions,
  type FlushQueueResult,
  type GhRunResult,
  type GhRunner,
  type ReportKind,
  type ToolReportEntry,
  type ToolReportOptions,
  type ToolReportPayload,
} from "./report.ts";

const BUILTIN_HARNESSES = [
  { id: "claude", label: "Claude Code" },
  { id: "codex", label: "OpenAI Codex" },
  { id: "cursor", label: "Cursor" },
  { id: "copilot", label: "GitHub Copilot" },
  { id: "grok", label: "Grok CLI" },
] as const;

function runDelegatedHookCmd(ctx: CommandRunContext): number {
  const code = handleHooksAndDoctorCli(ctx.cmd, ctx.rest, ctx.target, ctx.asJson);
  return code ?? 2;
}

registerCoreServices({ scanSingleFile });

export const harnessesPlugin = Plugin.define({
  id: "veristack.plugin.harnesses",
  setup(ctx) {
    registerCoreServices({ scanSingleFile });
    ctx.harness.transform((ed) => {
      for (const h of BUILTIN_HARNESSES) ed.add({ ...h });
    });
    ctx.command.transform((ed) => {
      ed.add({ id: "veristack.cmd.check-file", name: "check-file", usage: "vstack check-file <file> [--tier immediate|all] [--max-lines <n>] [--strict] [--json] [--fail]", run: runDelegatedHookCmd });
      ed.add({ id: "veristack.cmd.init", name: "init", usage: "vstack init [dir] [--force] [--no-hooks] [--harness ...] [--command <cmd>] [--json]", run: runDelegatedHookCmd });
      ed.add({ id: "veristack.cmd.hook", name: "hook", usage: "vstack hook <post-edit|pre-edit|stop> [--harness ...] [--tier immediate|all]", run: runDelegatedHookCmd });
      ed.add({ id: "veristack.cmd.hooks", name: "hooks", usage: "vstack hooks <on|off|status|reset> [dir] [--harness ...] [--command <cmd>] [--json]", run: runDelegatedHookCmd });
      ed.add({ id: "veristack.cmd.doctor", name: "doctor", usage: "vstack doctor [dir] [--json] [--fail]", run: runDelegatedHookCmd });
      ed.add({
        id: "veristack.cmd.report",
        name: "report",
        usage: "vstack report [--rule <id>] [--file <path[:line]>] [--kind fp|fn|crash|bug] [--reason <text>] [--command <cmd>] [--anonymize] [--local | --flush [--clear]] [--submit | --url | --out <file>] [--no-rerun] [--json]",
        run: (ctx) => handleReportCli(ctx.rest, ctx.asJson),
      });
    });
  },
});

export default harnessesPlugin;
