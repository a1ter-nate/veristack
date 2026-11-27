import {
  getCoreServices,
  Plugin,
  type CommandRunContext,
  type DiscoveredRepo,
  type Finding,
  type LanguagePluginSpec,
  type ScannedFile,
} from "@veristack/plugin";
import { lintCsharpStateMachines } from "@veristack/plugin-lang-csharp";
import { lintPythonStateMachines } from "@veristack/plugin-lang-python";
import { lintRustStateMachines } from "@veristack/plugin-lang-rust";
import { lintTsJsStateMachines } from "./ts-sm.ts";

export { lintTsJsStateMachines };

const GENERATED_PATH = /(?:^|\/)(?:generated|generated-clients?|codegen|__snapshots__)\/|\.(?:gen|generated)\.[cm]?[jt]sx?$/i;
const GENERATED_HEADER = /(?:@generated|auto-generated|do\s+not\s+edit|generated\s+by\b)/i;

export function lintImplicitStateMachinesInFile(
  file: ScannedFile,
  activeLanguages?: readonly LanguagePluginSpec[],
): Finding[] {
  if (file.isTest || /\.d\.[cm]?ts$|\.pyi$/i.test(file.rel)) return [];
  if (GENERATED_PATH.test(file.rel) && GENERATED_HEADER.test(file.content.slice(0, 600))) return [];
  if (activeLanguages) {
    const spec = activeLanguages.find((l) => l.id === file.language);
    if (!spec) return [];
    if (typeof spec.scanStateMachines === "function") return spec.scanStateMachines(file);
    if (file.language === "typescript" || file.language === "javascript") return lintTsJsStateMachines(file);
    return [];
  }
  if (file.language === "csharp") return lintCsharpStateMachines(file);
  if (file.language === "rust") return lintRustStateMachines(file);
  if (file.language === "python") return lintPythonStateMachines(file);
  if (file.language === "typescript" || file.language === "javascript") return lintTsJsStateMachines(file);
  return [];
}

export function analyzeStateMachines(
  repo: DiscoveredRepo,
  activeLanguages?: readonly LanguagePluginSpec[],
): Finding[] {
  const findings: Finding[] = [];
  for (const file of repo.files) {
    findings.push(...lintImplicitStateMachinesInFile(file, activeLanguages));
  }
  return findings;
}

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

function runStateMachinesCommand(ctx: CommandRunContext): number {
  const discover = getCoreServices().discoverRepo;
  if (!discover) throw new Error("Core discoverRepo service is not registered.");
  const findings = analyzeStateMachines(discover(ctx.target));
  console.log(formatFindings("no-implicit-state-machine", findings, ctx.asJson));
  return ctx.rest.includes("--fail") && findings.length > 0 ? 1 : 0;
}

export const stateMachinesPlugin = Plugin.define({
  id: "veristack.plugin.state-machines",
  setup(ctx) {
    ctx.analyzer.transform((ed) => {
      ed.add({
        id: "veristack.state-machines.audit",
        phase: "lint",
        run: (runCtx) => analyzeStateMachines(runCtx.repo, runCtx.activeLanguages),
      });
    });
    ctx.command.transform((ed) => {
      ed.add({
        id: "veristack.cmd.state-machines",
        name: "state-machines",
        usage: "vstack state-machines [dir] [--json] [--fail]",
        run: runStateMachinesCommand,
      });
    });
  },
});

export default stateMachinesPlugin;
