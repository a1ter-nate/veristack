import path from "node:path";
import { scanGitDiffCheats } from "@veristack/plugin-ci-auditor";
import { pathHelpers } from "@veristack/plugin";
import { runGitClean, soundnessClassForFinding } from "@veristack/plugin";
import type { Finding } from "@veristack/plugin";
import {
  collectSoundinessLedger,
  computeEmpiricalPrRisk,
  type EmpiricalPrRiskReport,
  type SoundinessSite,
} from "./empirical-risk.ts";

export type ReviewStakesTier = "critical" | "core" | "verify" | "low";

export interface ReviewFileItem {
  file: string;
  tier: ReviewStakesTier;
  added: number;
  deleted: number;
  reason: string;
  cheatCount: number;
}

export interface ReviewWorkaroundSignal {
  file: string;
  line: number;
  signal: string;
}

export interface ReviewBudgetBreach {
  rule: string;
  actual: number;
  limit: number;
  message: string;
  fix: string;
}

export interface ReviewBriefOptions {
  baseRef?: string;
  maxLines?: number;
  maxDirs?: number;
  maxDocLines?: number;
}

export interface ReviewBriefReport {
  schemaVersion: 1;
  repo: string;
  baseRef: string;
  passed: boolean;
  metrics: {
    filesChanged: number;
    dirsTouched: number;
    linesAdded: number;
    linesDeleted: number;
    netLines: number;
    nonLockfileLinesAdded: number;
    docLinesAdded: number;
    deletionRatio: number;
  };
  budgets: {
    maxLines: number;
    maxDirs: number;
    maxDocLines: number;
  };
  budgetBreaches: ReviewBudgetBreach[];
  cheatFindings: Finding[];
  workaroundSignals: ReviewWorkaroundSignal[];
  reviewQueue: {
    mustReview: ReviewFileItem[];
    coreLogic: ReviewFileItem[];
    verifyOracles: ReviewFileItem[];
    lowStakes: ReviewFileItem[];
  };
  blindSpots: string[];
  soundinessLedger?: SoundinessSite[];
  empiricalRisk?: EmpiricalPrRiskReport;
  ownershipChecklist: string[];
}

const LOCK_OR_GENERATED =
  /(?:^|\/)(?:pnpm-lock\.yaml|package-lock\.json|yarn\.lock|bun\.lockb?|cargo\.lock|uv\.lock|poetry\.lock|go\.sum)$|\.(?:snap|generated\.[a-z]+)$/i;
const DOC_FILE = /\.(?:md|mdx|txt|rst)$/i;
const CRITICAL_PATH =
  /(?:^|\/)(?:\.github\/workflows\/|codeowners$|migrations\/|schema|rls|policies\/|auth|security|billing|payment|permission|crypto|token|secret|openapi|contracts|state-machines?\/|tsconfig(?:\.[^/]+)?\.json$|\.?vstack\.json$|\.verification\/|package\.json$|cargo\.toml$|pyproject\.toml$|directory\.build\.props$)/i;
const WORKAROUND_MARKER = /\b(?:HACK|WORKAROUND|TEMP(?:ORARY)?|KLUDGE|FIXME)\b/;
const FALLBACK_SWALLOW_CATCH = /\bcatch\b[^{]*\{\s*return\s+(?:null|undefined|false|true|\[\s*\]|\{\s*\}|""|''|0)\s*;?\s*\}/;
const TIER_ORDER: Record<ReviewStakesTier, number> = { critical: 0, core: 1, verify: 2, low: 3 };

function validateBaseRef(baseRef: string): void {
  if (!baseRef || baseRef.startsWith("-")) {
    throw new Error(`Invalid git baseRef "${baseRef}".`);
  }
}

function classifyFileStakes(
  file: string,
  cheatCount: number,
  workaroundCount: number,
): { tier: ReviewStakesTier; reason: string } {
  if (cheatCount > 0) {
    return { tier: "critical", reason: `${cheatCount} diff-cheat / invariant-loss finding(s)` };
  }
  if (CRITICAL_PATH.test(file)) {
    return { tier: "critical", reason: "high-stakes boundary (security, schema, CI, contract, or strictness config)" };
  }
  if (workaroundCount > 0) {
    return { tier: "critical", reason: `${workaroundCount} workaround/fallback signal(s) added` };
  }
  if (LOCK_OR_GENERATED.test(file)) {
    return { tier: "low", reason: "lockfile or generated artifact" };
  }
  if (DOC_FILE.test(file)) {
    return { tier: "low", reason: "documentation / prose" };
  }
  if (pathHelpers.isTestFilePath(file)) {
    return { tier: "verify", reason: "test oracle / verification suite" };
  }
  return { tier: "core", reason: "production logic" };
}

function collectWorkaroundSignals(repoRoot: string, baseRef: string): ReviewWorkaroundSignal[] {
  const diff = runGitClean(repoRoot, ["diff", baseRef, "--unified=0", "--no-color"]);
  if (diff.status !== 0) return [];

  const signals: ReviewWorkaroundSignal[] = [];
  let currentFile = "";
  let currentLine = 1;

  for (const raw of diff.stdout.split(/\r?\n/)) {
    if (raw.startsWith("+++ b/")) {
      currentFile = raw.slice(6);
      continue;
    }
    const hunk = /^@@ -\d+(?:,\d+)? \+(\d+)/.exec(raw);
    if (hunk) {
      currentLine = Number(hunk[1]);
      continue;
    }
    if (!raw.startsWith("+") || raw.startsWith("+++")) continue;
    const added = raw.slice(1);
    if (!DOC_FILE.test(currentFile) && !LOCK_OR_GENERATED.test(currentFile) && !pathHelpers.isTestFilePath(currentFile)) {
      if (WORKAROUND_MARKER.test(added)) {
        signals.push({ file: currentFile, line: currentLine, signal: "workaround-marker" });
      } else if (FALLBACK_SWALLOW_CATCH.test(added)) {
        signals.push({ file: currentFile, line: currentLine, signal: "fallback-swallow-catch" });
      }
    }
    currentLine += 1;
  }
  return signals;
}

function buildBlindSpots(
  files: readonly ReviewFileItem[],
  docLinesAdded: number,
  additionBias: boolean,
): string[] {
  const spots: string[] = [
    "Static gates and agent reviews verify mechanics, not whether this change solves the right user problem.",
  ];
  if (files.some((f) => f.tier === "critical")) {
    spots.push("High-stakes paths changed: verify business intent, threat assumptions, and rollback safety by hand.");
  }
  if (additionBias) {
    spots.push("Diff is heavily additive: check whether existing code could be simplified or deleted instead of layered on.");
  }
  if (docLinesAdded > 0) {
    spots.push("Prose/docs were added: verify every paragraph earns the reader's time and reflects real code.");
  }
  if (files.some((f) => f.tier === "verify")) {
    spots.push("Tests were modified: confirm oracles come from an independent spec and failed before the fix.");
  }
  return spots;
}

function parseDiffNumstat(
  numstatOut: string,
  cheatsByFile: ReadonlyMap<string, number>,
  workaroundsByFile: ReadonlyMap<string, number>,
) {
  if (!numstatOut) return { items: [] as ReviewFileItem[], dirsTouched: 0, linesAdded: 0, linesDeleted: 0, nonLockfileLinesAdded: 0, docLinesAdded: 0, deletionRatio: 0 };
  const items: ReviewFileItem[] = [];
  const dirs = new Set<string>();
  let linesAdded = 0; let linesDeleted = 0; let nonLockfileLinesAdded = 0; let docLinesAdded = 0;
  for (const line of numstatOut.split(/\r?\n/)) {
    if (!line.trim()) continue;
    const [rawAdd, rawDel, ...restPath] = line.split("\t");
    const file = restPath.join("\t").trim();
    if (!file) continue;
    const added = rawAdd === "-" ? 0 : Number(rawAdd) || 0;
    const deleted = rawDel === "-" ? 0 : Number(rawDel) || 0;
    linesAdded += added; linesDeleted += deleted;
    if (!LOCK_OR_GENERATED.test(file)) {
      nonLockfileLinesAdded += added;
      const dir = path.posix.dirname(file);
      dirs.add(dir === "." ? "<root>" : dir);
    }
    if (DOC_FILE.test(file)) docLinesAdded += added;
    const cheatCount = cheatsByFile.get(file) ?? 0;
    const workaroundCount = workaroundsByFile.get(file) ?? 0;
    const classified = classifyFileStakes(file, cheatCount, workaroundCount);
    items.push({ file, tier: classified.tier, added, deleted, reason: classified.reason, cheatCount });
  }
  items.sort((a, b) => TIER_ORDER[a.tier] - TIER_ORDER[b.tier] || b.added + b.deleted - (a.added + a.deleted));
  const totalChurn = linesAdded + linesDeleted;
  const deletionRatio = totalChurn > 0 ? Number((linesDeleted / totalChurn).toFixed(3)) : 0;
  return { items, dirsTouched: dirs.size, linesAdded, linesDeleted, nonLockfileLinesAdded, docLinesAdded, deletionRatio };
}

interface ReviewBudgetInput {
  cheatFindings: readonly Finding[];
  workaroundSignals: readonly ReviewWorkaroundSignal[];
  stats: ReturnType<typeof parseDiffNumstat>;
  budgets: { maxLines: number; maxDirs: number; maxDocLines: number };
}

function evaluateReviewBudgets(input: ReviewBudgetInput): { breaches: ReviewBudgetBreach[]; additionBias: boolean } {
  const { cheatFindings, workaroundSignals, stats, budgets } = input;
  if (budgets.maxLines <= 0) throw new Error("maxLines must be positive");
  const additionBias = stats.nonLockfileLinesAdded >= 300 && stats.deletionRatio < 0.05 && stats.items.length >= 5;
  const breaches: ReviewBudgetBreach[] = [];
  if (cheatFindings.length > 0) {
    breaches.push({
      rule: "review-budget-diff-cheats", actual: cheatFindings.length, limit: 0,
      message: `${cheatFindings.length} anti-cheat / dropped-invariant violation(s) found in diff.`,
      fix: "Resolve every diff-cheats finding before requesting human review.",
    });
  }
  if (stats.nonLockfileLinesAdded > budgets.maxLines) {
    breaches.push({
      rule: "review-budget-diff-size", actual: stats.nonLockfileLinesAdded, limit: budgets.maxLines,
      message: `Diff adds ${stats.nonLockfileLinesAdded} non-lockfile lines (review budget: <= ${budgets.maxLines}).`,
      fix: "Split into stacked, independently reviewable PRs or delete redundant code before asking for review.",
    });
  }
  if (stats.dirsTouched > budgets.maxDirs) {
    breaches.push({
      rule: "review-budget-shotgun-spread", actual: stats.dirsTouched, limit: budgets.maxDirs,
      message: `Diff scatters changes across ${stats.dirsTouched} directories (budget: <= ${budgets.maxDirs}).`,
      fix: "Isolate unrelated refactors or consolidate leaky abstractions into a deeper module.",
    });
  }
  if (stats.docLinesAdded > budgets.maxDocLines) {
    breaches.push({
      rule: "review-budget-doc-dump", actual: stats.docLinesAdded, limit: budgets.maxDocLines,
      message: `Diff adds ${stats.docLinesAdded} lines of prose/docs (budget: <= ${budgets.maxDocLines}).`,
      fix: "Trim AI-generated prose so every line respects the reader's time.",
    });
  }
  if (additionBias) {
    breaches.push({
      rule: "review-budget-addition-bias", actual: Math.round(stats.deletionRatio * 100), limit: 5,
      message: `Heavily additive diff (+${stats.nonLockfileLinesAdded}/-${stats.linesDeleted}, ${(stats.deletionRatio * 100).toFixed(1)}% deletions across ${stats.items.length} files).`,
      fix: "Check for workarounds or parallel wrappers that should replace or delete existing code instead.",
    });
  }
  if (workaroundSignals.length > 0) {
    breaches.push({
      rule: "review-budget-workarounds", actual: workaroundSignals.length, limit: 0,
      message: `Added ${workaroundSignals.length} workaround/fallback-swallow signal(s) in production diff.`,
      fix: "Fix the root cause instead of layering HACK/WORKAROUND markers or silent fallback catches.",
    });
  }
  return { breaches, additionBias };
}

export function buildReviewBrief(repoPath: string, options: ReviewBriefOptions = {}): ReviewBriefReport {
  const repoRoot = path.resolve(repoPath);
  const baseRef = options.baseRef ?? "HEAD";
  validateBaseRef(baseRef);
  const budgets = { maxLines: options.maxLines ?? 600, maxDirs: options.maxDirs ?? 8, maxDocLines: options.maxDocLines ?? 250 };
  const numstat = runGitClean(repoRoot, ["diff", baseRef, "--numstat", "--no-renames"]);
  if (numstat.status !== 0) {
    throw new Error(`git diff failed for base "${baseRef}": ${(numstat.stderr ?? "").trim()}`);
  }
  const cheatFindings = scanGitDiffCheats(repoRoot, baseRef);
  const workaroundSignals = collectWorkaroundSignals(repoRoot, baseRef);
  const cheatsByFile = new Map<string, number>();
  for (const f of cheatFindings) cheatsByFile.set(f.file, (cheatsByFile.get(f.file) ?? 0) + 1);
  const workaroundsByFile = new Map<string, number>();
  for (const w of workaroundSignals) workaroundsByFile.set(w.file, (workaroundsByFile.get(w.file) ?? 0) + 1);
  const stats = parseDiffNumstat(numstat.stdout, cheatsByFile, workaroundsByFile);
  const soundinessLedger = collectSoundinessLedger(repoRoot, stats.items.map((i) => i.file));
  const empiricalRisk = computeEmpiricalPrRisk(repoRoot, stats.items.filter((i) => !LOCK_OR_GENERATED.test(i.file)));
  const hotspotByFile = new Map(empiricalRisk.files.map((f) => [f.file, f.hotspotPriority]));
  const sortedItems = [...stats.items].sort((a, b) =>
    TIER_ORDER[a.tier] - TIER_ORDER[b.tier] ||
    (hotspotByFile.get(b.file) ?? 0) - (hotspotByFile.get(a.file) ?? 0) ||
    b.added + b.deleted - (a.added + a.deleted),
  );
  const stampedCheats = cheatFindings.map((f) => (f.soundness ? f : { ...f, soundness: soundnessClassForFinding(f) }));
  const { breaches, additionBias } = evaluateReviewBudgets({ cheatFindings: stampedCheats, workaroundSignals, stats, budgets });
  const blindSpots = buildBlindSpots(sortedItems, stats.docLinesAdded, additionBias);
  if (soundinessLedger.length > 0) {
    blindSpots.push(`No fence yet on ${soundinessLedger.length} soundiness approximation site(s) (see Soundiness Ledger below).`);
  }
  return {
    schemaVersion: 1, repo: repoRoot, baseRef, passed: breaches.length === 0,
    metrics: {
      filesChanged: sortedItems.length, dirsTouched: stats.dirsTouched,
      linesAdded: stats.linesAdded, linesDeleted: stats.linesDeleted,
      netLines: stats.linesAdded - stats.linesDeleted,
      nonLockfileLinesAdded: stats.nonLockfileLinesAdded,
      docLinesAdded: stats.docLinesAdded, deletionRatio: stats.deletionRatio,
    },
    budgets, budgetBreaches: breaches, cheatFindings: stampedCheats, workaroundSignals,
    reviewQueue: {
      mustReview: sortedItems.filter((i) => i.tier === "critical"),
      coreLogic: sortedItems.filter((i) => i.tier === "core"),
      verifyOracles: sortedItems.filter((i) => i.tier === "verify"),
      lowStakes: sortedItems.filter((i) => i.tier === "low"),
    },
    blindSpots,
    soundinessLedger,
    empiricalRisk,
    ownershipChecklist: [
      "Problem & prior art understood before generation (no unreviewed first-draft pass-through).",
      "High-stakes slice (Must-Review queue above) verified directly by a human owner.",
      "Prefer subtraction: confirmed no workaround or parallel layer could be deleted/simplified.",
      "AI-authored code/docs explicitly disclosed and checked where stakes are highest.",
    ],
  };
}

export function formatReviewBriefTerminal(report: ReviewBriefReport): string {
  const m = report.metrics;
  const out: string[] = [];
  out.push(`Review Brief (${report.baseRef}) — ${report.passed ? "WITHIN BUDGET" : "OVER REVIEW BUDGET"}`);
  out.push(
    `Scope: ${m.filesChanged} file(s) across ${m.dirsTouched} dir(s) | +${m.linesAdded} / -${m.linesDeleted} (net ${m.netLines >= 0 ? "+" : ""}${m.netLines}, deletion ratio ${(m.deletionRatio * 100).toFixed(1)}%) | docs +${m.docLinesAdded}`,
  );
  if (report.empiricalRisk) {
    const er = report.empiricalRisk;
    out.push(`Empirical JIT Risk: entropy=${er.changeEntropy} | prior-fixes(NFIX)=${er.totalNfix} | max-hotspot=${er.maxHotspotPriority} | diffused-ownership=${er.ownershipDiffusionFiles}${er.shallowHistoryFallback ? " (shallow-clone fallback)" : ""}`);
  }
  if (report.budgetBreaches.length > 0) {
    out.push("");
    out.push(`SLOP-ASYMMETRY & BUDGET BREACHES (${report.budgetBreaches.length})`);
    for (const b of report.budgetBreaches) {
      out.push(`  - [${b.rule}] ${b.message}`);
      out.push(`      Fix: ${b.fix}`);
    }
  }
  const emitGroup = (label: string, items: readonly ReviewFileItem[], cap: number): void => {
    if (items.length === 0) return;
    out.push("");
    out.push(`${label} (${items.length})`);
    for (const item of items.slice(0, cap)) {
      out.push(`  - ${item.file} (+${item.added}/-${item.deleted}) — ${item.reason}`);
    }
    if (items.length > cap) out.push(`  ... and ${items.length - cap} more`);
  };
  emitGroup("MUST REVIEW FIRST (HIGH STAKES)", report.reviewQueue.mustReview, 15);
  emitGroup("CORE LOGIC", report.reviewQueue.coreLogic, 12);
  emitGroup("TEST ORACLES", report.reviewQueue.verifyOracles, 8);
  emitGroup("LOW STAKES / MECHANICAL", report.reviewQueue.lowStakes, 6);
  out.push("");
  out.push("WHERE AUTOMATED CHECKS ARE BLIND (HUMAN JUDGMENT REQUIRED)");
  for (const spot of report.blindSpots) out.push(`  - ${spot}`);
  if (report.soundinessLedger && report.soundinessLedger.length > 0) {
    out.push("", `SOUNDINESS LEDGER (${report.soundinessLedger.length} approximation site(s) — No fence yet)`);
    for (const s of report.soundinessLedger.slice(0, 15)) out.push(`  - [${s.kind}] ${s.file}:${s.line} — ${s.snippet}`);
  }
  return out.join("\n");
}

export function formatReviewBriefMarkdown(report: ReviewBriefReport): string {
  if (!report.repo) throw new Error("report.repo is required");
  const m = report.metrics;
  const out: string[] = [];
  out.push(`## Human Review Brief (\`${report.baseRef}\`) — ${report.passed ? "Within Budget" : "Attention Required"}`);
  out.push("");
  out.push(
    `- **Diff Shape:** ${m.filesChanged} files · ${m.dirsTouched} dirs · \`+${m.linesAdded} / -${m.linesDeleted}\` (deletion ratio \`${(m.deletionRatio * 100).toFixed(1)}%\`) · docs \`+${m.docLinesAdded}\``,
  );
  if (report.budgetBreaches.length > 0) {
    out.push("");
    out.push("### Slop-Asymmetry Warnings");
    for (const b of report.budgetBreaches) {
      out.push(`- **\`${b.rule}\`**: ${b.message} *Fix:* ${b.fix}`);
    }
  }
  const topFocus = [...report.reviewQueue.mustReview, ...report.reviewQueue.coreLogic].slice(0, 12);
  if (topFocus.length > 0) {
    out.push("");
    out.push("### Highest-Stakes Files to Read First");
    out.push("| Priority | File | Churn | Why |");
    out.push("| :---: | :--- | :---: | :--- |");
    for (const f of topFocus) {
      out.push(`| \`${f.tier}\` | \`${f.file}\` | \`+${f.added}/-${f.deleted}\` | ${f.reason} |`);
    }
  }
  out.push("");
  out.push("### Where Linters & Tests Are Blind");
  for (const spot of report.blindSpots) out.push(`- ${spot}`);
  out.push("");
  out.push("### Human Ownership Checklist");
  for (const item of report.ownershipChecklist) out.push(`- [ ] ${item}`);
  return out.join("\n");
}
