import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { scanRepo } from "../ladder.ts";

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

export interface BenchReport {
  passed: boolean;
  totalExpectedRules: number;
  totalMatchedRules: number;
  totalCleanFps: number;
  totalAdversarialFps: number;
  totalScanMs: number;
  languages: BenchLanguageResult[];
  corpusFindingsPer10kLoc?: number;
}

interface ExampleManifest {
  language: string;
  caught: Record<string, string[]>;
  clean: string[];
}

function commentPrefix(lang: string): string {
  return lang === "python" ? "# " : "// ";
}

function wrapInComments(content: string, lang: string): string {
  const prefix = commentPrefix(lang);
  return content
    .split(/\r?\n/)
    .map((line) => `${prefix}${line}`)
    .join("\n");
}

function wrapInStringLiteral(content: string, lang: string): string {
  const escaped = content.replace(/\\/g, "\\\\").replace(/"/g, '\\"').replace(/\r?\n/g, "\\n");
  if (lang === "python") return `DOC = "${escaped}"\n`;
  if (lang === "rust") return `pub const DOC: &str = "${escaped}";\n`;
  if (lang === "csharp") return `public static class Doc { public const string Text = "${escaped}"; }\n`;
  return `export const DOC = "${escaped}";\n`;
}

function runInTempDir(files: Record<string, string>): ReturnType<typeof scanRepo> {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "vstack-bench-"));
  try {
    for (const [rel, content] of Object.entries(files)) {
      const full = path.join(dir, rel);
      fs.mkdirSync(path.dirname(full), { recursive: true });
      fs.writeFileSync(full, content, "utf8");
    }
    return scanRepo(dir);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

export function runPrecisionBench(repoRoot: string, corpusDir?: string): BenchReport {
  const examplesRoot = path.join(repoRoot, "examples");
  const langs = ["typescript", "csharp", "rust", "python"] as const;
  const languages: BenchLanguageResult[] = [];

  for (const lang of langs) {
    const langDir = path.join(examplesRoot, lang);
    const manifestPath = path.join(langDir, "manifest.json");
    if (!fs.existsSync(manifestPath)) continue;

    const manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8")) as ExampleManifest;
    const caughtDir = path.join(langDir, "caught");
    const cleanDir = path.join(langDir, "clean");

    const t0 = performance.now();
    const caughtScan = scanRepo(caughtDir);
    const cleanScan = scanRepo(cleanDir);
    const scanMs = Number((performance.now() - t0).toFixed(2));

    let expectedRules = 0;
    let matchedRules = 0;
    const missedRules: string[] = [];

    for (const [relFile, expected] of Object.entries(manifest.caught)) {
      const observed = new Set(caughtScan.findings.filter((f) => f.file === relFile).map((f) => f.rule));
      for (const r of expected) {
        expectedRules += 1;
        if (observed.has(r)) matchedRules += 1;
        else missedRules.push(`${relFile}:${r}`);
      }
    }

    const cleanFalsePositives: string[] = [];
    for (const relFile of manifest.clean) {
      for (const f of cleanScan.findings.filter((x) => x.file === relFile)) {
        cleanFalsePositives.push(`${relFile}:${f.rule}@${f.line}`);
      }
    }

    const commentedFiles: Record<string, string> = {};
    const stringFiles: Record<string, string> = {};
    for (const relFile of Object.keys(manifest.caught)) {
      if (/test|spec/i.test(relFile)) continue;
      const content = fs.readFileSync(path.join(caughtDir, relFile), "utf8");
      commentedFiles[relFile] = wrapInComments(content, lang);
      stringFiles[relFile] = wrapInStringLiteral(content, lang);
    }

    const commentScan = runInTempDir(commentedFiles);
    const commentWrappedFps = commentScan.findings
      .filter((f) => f.rule !== "no-comments" && f.rule !== "suppression-audit")
      .map((f) => `${f.file}:${f.rule}@${f.line}`);

    const stringScan = runInTempDir(stringFiles);
    const stringWrappedFps = stringScan.findings
      .filter((f) => f.rule !== "no-comments" && f.rule !== "max-file-lines")
      .map((f) => `${f.file}:${f.rule}@${f.line}`);

    languages.push({
      language: lang,
      caughtFiles: Object.keys(manifest.caught).length,
      cleanFiles: manifest.clean.length,
      expectedRules,
      matchedRules,
      missedRules,
      cleanFalsePositives,
      commentWrappedFps,
      stringWrappedFps,
      scanMs,
    });
  }

  let corpusFindingsPer10kLoc: number | undefined;
  if (corpusDir && fs.existsSync(corpusDir)) {
    const corpusReport = scanRepo(corpusDir);
    const loc = Math.max(1, corpusReport.summary.prodLines + corpusReport.summary.testLines);
    corpusFindingsPer10kLoc = Number(((corpusReport.findings.length / loc) * 10_000).toFixed(2));
  }

  const totalExpectedRules = languages.reduce((s, l) => s + l.expectedRules, 0);
  const totalMatchedRules = languages.reduce((s, l) => s + l.matchedRules, 0);
  const totalCleanFps = languages.reduce((s, l) => s + l.cleanFalsePositives.length, 0);
  const totalAdversarialFps = languages.reduce((s, l) => s + l.commentWrappedFps.length + l.stringWrappedFps.length, 0);
  const totalScanMs = Number(languages.reduce((s, l) => s + l.scanMs, 0).toFixed(2));

  return {
    passed: totalExpectedRules === totalMatchedRules && totalCleanFps === 0 && totalAdversarialFps === 0,
    totalExpectedRules,
    totalMatchedRules,
    totalCleanFps,
    totalAdversarialFps,
    totalScanMs,
    languages,
    corpusFindingsPer10kLoc,
  };
}

export function formatBenchReport(report: BenchReport): string {
  const lines = [
    `vstack bench [${report.passed ? "PASS" : "FAIL"}]: recall=${report.totalMatchedRules}/${report.totalExpectedRules} | cleanFPs=${report.totalCleanFps} | adversarialFPs=${report.totalAdversarialFps} | scanMs=${report.totalScanMs}ms`,
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
  return lines.join("\n");
}
