import { Plugin, type CommandRunContext } from "@veristack/plugin";
import { buildReviewBrief, formatReviewBriefMarkdown, formatReviewBriefTerminal } from "./review-brief.ts";

export {
  buildReviewBrief,
  formatReviewBriefMarkdown,
  formatReviewBriefTerminal,
  type ReviewBriefOptions,
  type ReviewBriefReport,
} from "./review-brief.ts";

function parseFlagValue(args: readonly string[], flag: string): string | undefined {
  for (let i = 0; i < args.length; i++) {
    const a = args[i] ?? "";
    if (a === flag) return args[i + 1];
    if (a.startsWith(`${flag}=`)) return a.slice(flag.length + 1);
  }
  return undefined;
}

function runReviewBriefCommand(ctx: CommandRunContext): number {
  const maxLinesRaw = parseFlagValue(ctx.rest, "--max-lines");
  const maxDirsRaw = parseFlagValue(ctx.rest, "--max-dirs");
  const maxDocRaw = parseFlagValue(ctx.rest, "--max-doc-lines");
  const report = buildReviewBrief(ctx.target, {
    baseRef: parseFlagValue(ctx.rest, "--base") ?? "HEAD",
    maxLines: maxLinesRaw ? Number(maxLinesRaw) : undefined,
    maxDirs: maxDirsRaw ? Number(maxDirsRaw) : undefined,
    maxDocLines: maxDocRaw ? Number(maxDocRaw) : undefined,
  });
  if (ctx.asJson) console.log(JSON.stringify(report, null, 2));
  else if (ctx.asMd) console.log(formatReviewBriefMarkdown(report));
  else console.log(formatReviewBriefTerminal(report));
  return ctx.rest.includes("--fail") && !report.passed ? 1 : 0;
}

export const reviewBriefPlugin = Plugin.define({
  id: "veristack.plugin.review-brief",
  setup(ctx) {
    ctx.command.transform((ed) => {
      ed.add({
        id: "veristack.cmd.review-brief",
        name: "review-brief",
        usage: "vstack review-brief [dir] [--base <ref>] [--max-lines <n>] [--max-dirs <n>] [--max-doc-lines <n>] [--json | --md] [--fail]",
        run: runReviewBriefCommand,
      });
    });
  },
});

export default reviewBriefPlugin;
