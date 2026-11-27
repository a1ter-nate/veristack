import { getCoreServices, Plugin, registerCoreServices, type CommandRunContext, type Finding } from "@veristack/plugin";
import { auditCiWorkflows, scanGitDiffCheats } from "./ci-auditor.ts";
import { extractSignals } from "./signals.ts";
import { auditCodeownersPerimeter, checkGitHubBranchProtection } from "./workflow-audit.ts";

export { auditCiWorkflows, scanGitDiffCheats } from "./ci-auditor.ts";
export { auditExtendedCiRules, auditMaestroFlow } from "./ci-workflow-rules.ts";
export { extractSignals } from "./signals.ts";
export {
  auditCodeownersPerimeter,
  checkGitHubBranchProtection,
  evaluateBranchProtectionJson,
  globMatchesPath,
  parseGitHubWorkflow,
  type CodeownersPerimeterResult,
} from "./workflow-audit.ts";

function parseFlagValue(args: readonly string[], flag: string): string | undefined {
  for (let i = 0; i < args.length; i++) {
    const a = args[i] ?? "";
    if (a === flag) return args[i + 1];
    if (a.startsWith(`${flag}=`)) return a.slice(flag.length + 1);
  }
  return undefined;
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

function runDiffCheatsCommand(ctx: CommandRunContext): number {
  const baseRef = parseFlagValue(ctx.rest, "--base") ?? "HEAD";
  const findings = scanGitDiffCheats(ctx.target, baseRef);
  console.log(formatFindings(`diff-cheats (${baseRef})`, findings, ctx.asJson));
  return ctx.rest.includes("--fail") && findings.length > 0 ? 1 : 0;
}

function runPerimeterCommand(ctx: CommandRunContext): number {
  const discover = getCoreServices().discoverRepo;
  if (!discover) throw new Error("Core discoverRepo service is not registered.");
  const repo = discover(ctx.target);
  const co = auditCodeownersPerimeter(repo.files, repo.allRelPaths);
  const gh = ctx.rest.includes("--check-github") ? checkGitHubBranchProtection(repo.root) : undefined;
  const passed = co.passed && (!gh || gh.passed);
  if (ctx.asJson) console.log(JSON.stringify({ passed, codeowners: co, branchProtection: gh }, null, 2));
  else {
    console.log(`perimeter [${passed ? "PASS" : "FAIL"}]: CODEOWNERS=${co.passed ? "LOCKED" : `UNCOVERED (${co.uncoveredSurfaces.join(", ")})`}`);
    if (gh) console.log(`  GitHub branch protection: ${gh.passed ? "PASS" : "FAIL"} — ${gh.detail}`);
  }
  return ctx.rest.includes("--fail") && !passed ? 1 : 0;
}

registerCoreServices({ scanGitDiffCheats });

export const ciAuditorPlugin = Plugin.define({
  id: "veristack.plugin.ci-auditor",
  setup(ctx) {
    if (!ctx) throw new Error("Plugin context is required.");
    registerCoreServices({ scanGitDiffCheats });
    ctx.signal.transform((ed) => {
      ed.add({
        id: "veristack.ci-auditor.signals",
        extract: (input) => extractSignals(input.files, input.allRelPaths, input.languages, input.defaultBranch),
      });
    });
    ctx.analyzer.transform((ed) => {
      ed.add({
        id: "veristack.ci-auditor.workflows",
        phase: "lint",
        run: (runCtx) => auditCiWorkflows(runCtx.repo),
      });
    });
    ctx.command.transform((ed) => {
      ed.add({
        id: "veristack.cmd.diff-cheats",
        name: "diff-cheats",
        usage: "vstack diff-cheats [dir] [--base <ref>] [--json] [--fail]",
        run: runDiffCheatsCommand,
      });
      ed.add({
        id: "veristack.cmd.perimeter",
        name: "perimeter",
        usage: "vstack perimeter [dir] [--check-github] [--json] [--fail]",
        run: runPerimeterCommand,
      });
    });
  },
});

export default ciAuditorPlugin;
