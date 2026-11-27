import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { auditDiffInvariantLoss, auditTsAstPredicateDrop, buildSyntheticRevertEvents } from "@veristack/plugin-lang-typescript";
import { getCoreServices, type Finding, type ScanReport } from "@veristack/plugin";
import { auditDiffAntiEvasion } from "@veristack/plugin-control-plane";

export interface BenchLanguageResult {
  language: string;
  caughtFiles: number;
  cleanFiles: number;
  expectedRules: number;
  matchedRules: number;
  missedRules: string[];
  cleanFalsePositives: string[];
  commentWrappedFps: string[];
  stringWrappedFps: string[];
  scanMs: number;
}

export interface ReplayPairResult {
  id: string;
  repo: string;
  sha: string;
  lang: string;
  subject: string;
  shapes: string[];
  caughtRules: string[];
  regressedRules: string[];
  caught: boolean;
}

export interface ReplayBenchReport {
  corpusDir: string;
  totalPairs: number;
  caughtPairs: number;
  catchRatePct: number;
  regressionCaughtPairs: number;
  regressionImmunityPct: number;
  combinedCaughtPairs: number;
  combinedRatePct: number;
  cleanAfterPairs: number;
  scanMs: number;
  byLanguage: Record<string, { total: number; caught: number; pct: number; regressionCaught: number }>;
  topCaughtRules: Array<{ rule: string; count: number }>;
  topLostInvariants: Array<{ invariant: string; count: number }>;
  topEscapedShapes: Array<{ shape: string; escaped: number; total: number }>;
  escapedSamples: Array<{ id: string; repo: string; lang: string; subject: string; shapes: string[] }>;
}

export interface BenchReport {
  passed: boolean;
  totalExpectedRules: number;
  totalMatchedRules: number;
  totalCleanFps: number;
  totalAdversarialFps: number;
  totalScanMs: number;
  languages: BenchLanguageResult[];
  corpusFindingsPer10kLoc?: number;
  replay?: ReplayBenchReport;
}

interface ExampleManifest {
  language: string;
  caught: Record<string, string[]>;
  clean: string[];
}

function commentPrefix(lang: string): string {
  if (lang === "python" || lang === "shell") return "# ";
  if (lang === "sql") return "-- ";
  return "// ";
}

function wrapInComments(content: string, lang: string): string {
  const prefix = commentPrefix(lang);
  return content
    .split(/\r?\n/)
    .map((line) => `${prefix}${line}`)
    .join("\n");
}

function wrapInStringLiteral(content: string, lang: string): string | null {
  if (lang === "sql" || lang === "shell") return null;
  const escaped = content.replace(/\\/g, "\\\\").replace(/"/g, '\\"').replace(/\r?\n/g, "\\n");
  if (lang === "python") return `DOC = "${escaped}"\n`;
  if (lang === "rust") return `pub const DOC: &str = "${escaped}";\n`;
  if (lang === "csharp") return `public static class Doc { public const string Text = "${escaped}"; }\n`;
  if (lang === "go") return `package doc\nconst Doc = "${escaped}"\n`;
  return `export const DOC = "${escaped}";\n`;
}

function runInTempDir(files: Record<string, string>): ScanReport {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "vstack-bench-"));
  try {
    for (const [rel, content] of Object.entries(files)) {
      const full = path.join(dir, rel);
      fs.mkdirSync(path.dirname(full), { recursive: true });
      fs.writeFileSync(full, content, "utf8");
    }
    return (getCoreServices().scanRepo ?? (() => { throw new Error("Core scanRepo service not registered."); }))(dir);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

interface ReplayManifestEntry {
  id: string;
  repo: string;
  sha: string;
  subject: string;
  lang: string;
  beforeRel: string;
  afterRel: string;
  shapes: string[];
}

function countRuleMap(findings: readonly { rule: string }[]): Map<string, number> {
  const m = new Map<string, number>();
  for (const f of findings) {
    if (f.rule === "no-comments" || f.rule === "max-file-lines" || f.rule === "max-exports-per-module" || f.rule === "wide-directory") {
      continue;
    }
    m.set(f.rule, (m.get(f.rule) ?? 0) + 1);
  }
  return m;
}

function groupFindingsByFile(findings: readonly { file: string; rule: string }[]): Map<string, Array<{ rule: string }>> {
  const byFile = new Map<string, Array<{ rule: string }>>();
  for (const f of findings) {
    const arr = byFile.get(f.file) ?? [];
    arr.push(f);
    byFile.set(f.file, arr);
  }
  return byFile;
}

function evaluateReplayPair(
  entry: ReplayManifestEntry,
  ctx: {
    replayDir: string;
    beforeByFile: Map<string, Array<{ rule: string }>>;
    afterByFile: Map<string, Array<{ rule: string }>>;
    caughtRuleCounts: Map<string, number>;
    lostInvariantCounts: Map<string, number>;
  },
): { caught: boolean; regressionCaught: boolean; cleanAfter: boolean } {
  if (!entry.beforeRel) throw new Error("Replay entry requires beforeRel.");
  const bMap = countRuleMap(ctx.beforeByFile.get(entry.beforeRel) ?? []);
  const aMap = countRuleMap(ctx.afterByFile.get(entry.afterRel) ?? []);
  let caughtCount = 0;
  let regressedCount = 0;
  for (const [rule, bCnt] of bMap.entries()) {
    if (bCnt > (aMap.get(rule) ?? 0)) {
      caughtCount += 1;
      ctx.caughtRuleCounts.set(rule, (ctx.caughtRuleCounts.get(rule) ?? 0) + 1);
    }
  }
  for (const [rule, aCnt] of aMap.entries()) {
    if (aCnt > (bMap.get(rule) ?? 0)) regressedCount += 1;
  }
  const beforeRaw = fs.readFileSync(path.join(ctx.replayDir, "before", entry.beforeRel), "utf8");
  const afterRaw = fs.readFileSync(path.join(ctx.replayDir, "after", entry.afterRel), "utf8");
  const revertEvents = buildSyntheticRevertEvents(entry.afterRel, afterRaw, beforeRaw);
  const revertFindings = [
    ...auditDiffInvariantLoss(revertEvents),
    ...auditTsAstPredicateDrop(entry.afterRel, afterRaw, beforeRaw),
    ...auditDiffAntiEvasion(revertEvents),
  ];
  for (const rf of revertFindings) {
    const m = /removed a '([^']+)' invariant/.exec(rf.message);
    const label = m?.[1] ?? rf.rule;
    ctx.lostInvariantCounts.set(label, (ctx.lostInvariantCounts.get(label) ?? 0) + 1);
  }
  return { caught: caughtCount > 0, regressionCaught: revertFindings.length > 0, cleanAfter: regressedCount === 0 };
}

export function runHistoricalReplayBench(replayDir: string): ReplayBenchReport {
  if (!replayDir) throw new Error("replayDir is required.");
  const manifestPath = path.join(replayDir, "manifest.json");
  if (!fs.existsSync(manifestPath)) throw new Error(`Missing replay manifest: ${manifestPath}`);
  const entries = JSON.parse(fs.readFileSync(manifestPath, "utf8")) as ReplayManifestEntry[];
  const t0 = performance.now();
  const beforeByFile = groupFindingsByFile((getCoreServices().scanRepo ?? (() => { throw new Error("Core scanRepo service not registered."); }))(path.join(replayDir, "before")).findings);
  const afterByFile = groupFindingsByFile((getCoreServices().scanRepo ?? (() => { throw new Error("Core scanRepo service not registered."); }))(path.join(replayDir, "after")).findings);
  const scanMs = Number((performance.now() - t0).toFixed(2));

  let caughtPairs = 0; let regressionCaughtPairs = 0; let combinedCaughtPairs = 0; let cleanAfterPairs = 0;
  const byLanguage: Record<string, { total: number; caught: number; pct: number; regressionCaught: number }> = {};
  const caughtRuleCounts = new Map<string, number>();
  const lostInvariantCounts = new Map<string, number>();
  const shapeStats = new Map<string, { escaped: number; total: number }>();
  const escapedSamples: ReplayBenchReport["escapedSamples"] = [];

  for (const entry of entries) {
    const { caught, regressionCaught, cleanAfter } = evaluateReplayPair(entry, { replayDir, beforeByFile, afterByFile, caughtRuleCounts, lostInvariantCounts });
    if (caught) caughtPairs += 1;
    if (regressionCaught) regressionCaughtPairs += 1;
    if (caught || regressionCaught) combinedCaughtPairs += 1;
    if (cleanAfter) cleanAfterPairs += 1;

    const langSlot = byLanguage[entry.lang] ?? { total: 0, caught: 0, pct: 0, regressionCaught: 0 };
    langSlot.total += 1;
    if (caught) langSlot.caught += 1;
    if (regressionCaught) langSlot.regressionCaught += 1;
    langSlot.pct = Number(((langSlot.caught / langSlot.total) * 100).toFixed(1));
    byLanguage[entry.lang] = langSlot;

    for (const sh of entry.shapes.length > 0 ? entry.shapes : ["unclustered"]) {
      const s = shapeStats.get(sh) ?? { escaped: 0, total: 0 };
      s.total += 1;
      if (!caught && !regressionCaught) s.escaped += 1;
      shapeStats.set(sh, s);
    }
    if (!caught && !regressionCaught && escapedSamples.length < 40) {
      escapedSamples.push({ id: entry.id, repo: entry.repo, lang: entry.lang, subject: entry.subject, shapes: entry.shapes });
    }
  }

  return {
    corpusDir: replayDir, totalPairs: entries.length, caughtPairs,
    catchRatePct: Number(((caughtPairs / Math.max(1, entries.length)) * 100).toFixed(1)),
    regressionCaughtPairs,
    regressionImmunityPct: Number(((regressionCaughtPairs / Math.max(1, entries.length)) * 100).toFixed(1)),
    combinedCaughtPairs,
    combinedRatePct: Number(((combinedCaughtPairs / Math.max(1, entries.length)) * 100).toFixed(1)),
    cleanAfterPairs, scanMs, byLanguage,
    topCaughtRules: [...caughtRuleCounts.entries()].sort((a, b) => b[1] - a[1]).slice(0, 20).map(([rule, count]) => ({ rule, count })),
    topLostInvariants: [...lostInvariantCounts.entries()].sort((a, b) => b[1] - a[1]).slice(0, 12).map(([invariant, count]) => ({ invariant, count })),
    topEscapedShapes: [...shapeStats.entries()].sort((a, b) => b[1].escaped - a[1].escaped).slice(0, 15).map(([shape, v]) => ({ shape, escaped: v.escaped, total: v.total })),
    escapedSamples,
  };
}

function runLanguagePrecisionBench(examplesRoot: string, lang: string): BenchLanguageResult | null {
  if (!lang) return null;
  const langDir = path.join(examplesRoot, lang);
  const manifestPath = path.join(langDir, "manifest.json");
  if (!fs.existsSync(manifestPath)) return null;
  const manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8")) as ExampleManifest;
  const caughtDir = path.join(langDir, "caught");
  const cleanDir = path.join(langDir, "clean");
  const t0 = performance.now();
  const caughtScan = (getCoreServices().scanRepo ?? (() => { throw new Error("Core scanRepo service not registered."); }))(caughtDir);
  const cleanScan = (getCoreServices().scanRepo ?? (() => { throw new Error("Core scanRepo service not registered."); }))(cleanDir);
  const scanMs = Number((performance.now() - t0).toFixed(2));

  let expectedRules = 0; let matchedRules = 0;
  const missedRules: string[] = [];
  for (const [relFile, expected] of Object.entries(manifest.caught)) {
    const observed = new Set(caughtScan.findings.filter((f: Finding) => f.file === relFile).map((f: Finding) => f.rule));
    for (const r of expected) {
      expectedRules += 1;
      if (observed.has(r)) matchedRules += 1;
      else missedRules.push(`${relFile}:${r}`);
    }
  }
  const cleanFalsePositives: string[] = [];
  for (const relFile of manifest.clean) {
    for (const f of cleanScan.findings.filter((x) => x.file === relFile)) cleanFalsePositives.push(`${relFile}:${f.rule}@${f.line}`);
  }
  const commentedFiles: Record<string, string> = {};
  const stringFiles: Record<string, string> = {};
  for (const relFile of Object.keys(manifest.caught)) {
    if (/test|spec/i.test(relFile)) continue;
    const content = fs.readFileSync(path.join(caughtDir, relFile), "utf8");
    commentedFiles[relFile] = wrapInComments(content, lang);
    const wrappedStr = wrapInStringLiteral(content, lang);
    if (wrappedStr !== null) stringFiles[relFile] = wrappedStr;
  }
  const commentWrappedFps = runInTempDir(commentedFiles).findings
    .filter((f: Finding) => f.rule !== "no-comments" && f.rule !== "suppression-audit")
    .map((f: Finding) => `${f.file}:${f.rule}@${f.line}`);
  const stringWrappedFps = (Object.keys(stringFiles).length > 0 ? runInTempDir(stringFiles).findings : [])
    .filter((f: Finding) => f.rule !== "no-comments" && f.rule !== "max-file-lines")
    .map((f: Finding) => `${f.file}:${f.rule}@${f.line}`);

  return {
    language: lang, caughtFiles: Object.keys(manifest.caught).length, cleanFiles: manifest.clean.length,
    expectedRules, matchedRules, missedRules, cleanFalsePositives, commentWrappedFps, stringWrappedFps, scanMs,
  };
}

export function runPrecisionBench(repoRoot: string, corpusDir?: string, replayDir?: string): BenchReport {
  if (!repoRoot) throw new Error("repoRoot is required.");
  const examplesRoot = path.join(repoRoot, "examples");
  const langs = ["typescript", "csharp", "rust", "python", "go", "sql", "shell"] as const;
  const languages: BenchLanguageResult[] = [];
  if (fs.existsSync(examplesRoot)) {
    for (const lang of langs) {
      const result = runLanguagePrecisionBench(examplesRoot, lang);
      if (result) languages.push(result);
    }
  }

  const resolvedCorpus = corpusDir ? (path.isAbsolute(corpusDir) ? corpusDir : path.resolve(repoRoot, corpusDir)) : undefined;
  let corpusFindingsPer10kLoc: number | undefined;
  let corpusScanMs = 0;
  if (resolvedCorpus && fs.existsSync(resolvedCorpus)) {
    const t0 = performance.now();
    const corpusReport = (getCoreServices().scanRepo ?? (() => { throw new Error("Core scanRepo service not registered."); }))(resolvedCorpus);
    corpusScanMs = Number((performance.now() - t0).toFixed(2));
    const loc = Math.max(1, corpusReport.summary.prodLines + corpusReport.summary.testLines);
    corpusFindingsPer10kLoc = Number(((corpusReport.findings.length / loc) * 10_000).toFixed(2));
  }

  const totalExpectedRules = languages.reduce((s, l) => s + l.expectedRules, 0);
  const totalMatchedRules = languages.reduce((s, l) => s + l.matchedRules, 0);
  const totalCleanFps = languages.reduce((s, l) => s + l.cleanFalsePositives.length, 0);
  const totalAdversarialFps = languages.reduce((s, l) => s + l.commentWrappedFps.length + l.stringWrappedFps.length, 0);
  const totalScanMs = Number((languages.reduce((s, l) => s + l.scanMs, 0) + corpusScanMs).toFixed(2));
  const resolvedReplay = replayDir ? (path.isAbsolute(replayDir) ? replayDir : path.resolve(repoRoot, replayDir)) : undefined;
  const replay = resolvedReplay && fs.existsSync(path.join(resolvedReplay, "manifest.json")) ? runHistoricalReplayBench(resolvedReplay) : undefined;
  const replayPassed = !replay || replay.totalPairs === 0 || (replay.combinedCaughtPairs > 0 && replay.cleanAfterPairs === replay.totalPairs);
  const hasCorpusOrReplay = corpusFindingsPer10kLoc !== undefined || Boolean(replay);
  const examplesPassed = totalExpectedRules > 0
    ? totalExpectedRules === totalMatchedRules && totalCleanFps === 0 && totalAdversarialFps === 0
    : hasCorpusOrReplay;

  return {
    passed: examplesPassed && replayPassed,
    totalExpectedRules, totalMatchedRules, totalCleanFps, totalAdversarialFps, totalScanMs, languages, corpusFindingsPer10kLoc, replay,
  };
}

export function formatBenchReport(report: BenchReport): string {
  const recallText = report.totalExpectedRules > 0
    ? `${report.totalMatchedRules}/${report.totalExpectedRules}`
    : report.corpusFindingsPer10kLoc !== undefined || report.replay
      ? "N/A"
      : "0/0";
  const lines = [
    `vstack bench [${report.passed ? "PASS" : "FAIL"}]: recall=${recallText} | cleanFPs=${report.totalCleanFps} | adversarialFPs=${report.totalAdversarialFps} | scanMs=${report.totalScanMs}ms`,
  ];
  if (report.corpusFindingsPer10kLoc !== undefined) {
    lines.push(`  corpus density: ${report.corpusFindingsPer10kLoc} findings / 10k LOC`);
  }
  for (const l of report.languages) {
    lines.push(
      `  - ${l.language.padEnd(10)} recall=${l.matchedRules}/${l.expectedRules} cleanFPs=${l.cleanFalsePositives.length} commentFPs=${l.commentWrappedFps.length} stringFPs=${l.stringWrappedFps.length} (${l.scanMs}ms)`,
    );
    for (const m of l.missedRules) lines.push(`      MISSED: ${m}`);
    for (const fp of [...l.cleanFalsePositives, ...l.commentWrappedFps, ...l.stringWrappedFps]) {
      lines.push(`      FP: ${fp}`);
    }
  }
  if (report.replay) {
    const r = report.replay;
    lines.push(
      `  historical replay: forwardCaught=${r.caughtPairs}/${r.totalPairs} (${r.catchRatePct}%) | regressionImmunity=${r.regressionCaughtPairs}/${r.totalPairs} (${r.regressionImmunityPct}%) | combined=${r.combinedCaughtPairs}/${r.totalPairs} (${r.combinedRatePct}%) | regressionFree=${r.cleanAfterPairs}/${r.totalPairs} (${r.scanMs}ms)`,
    );
    for (const [lang, stats] of Object.entries(r.byLanguage).sort()) {
      lines.push(`    - ${lang.padEnd(10)} forward=${stats.caught}/${stats.total} (${stats.pct}%) | invLoss=${stats.regressionCaught}/${stats.total}`);
    }
    if (r.topCaughtRules.length > 0) {
      lines.push(`    top caught rules: ${r.topCaughtRules.slice(0, 8).map((x) => `${x.rule}(${x.count})`).join(", ")}`);
    }
    if (r.topLostInvariants.length > 0) {
      lines.push(`    top protected invariants: ${r.topLostInvariants.slice(0, 8).map((x) => `${x.invariant}(${x.count})`).join(", ")}`);
    }
    if (r.topEscapedShapes.length > 0) {
      lines.push(`    top escaped shapes: ${r.topEscapedShapes.slice(0, 6).map((x) => `${x.shape}(${x.escaped}/${x.total})`).join(", ")}`);
    }
  }
  return lines.join("\n");
}
