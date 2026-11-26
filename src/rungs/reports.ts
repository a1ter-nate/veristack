import fs from "node:fs";
import path from "node:path";

interface StructuredReportMetrics {
  testsPassed?: number;
  testsFailed?: number;
  testsSkipped?: number;
  mutationScore?: number;
  lineCoveragePct?: number;
  fileCoverage: Map<string, number>;
}

interface CrapEntry {
  file: string;
  cyclomaticComplexity: number;
  coveragePct: number;
  crapScore: number;
}

interface CrapReport {
  maxAllowed: number;
  passed: boolean;
  worstCrap: number;
  offenders: CrapEntry[];
  evaluatedFiles: number;
}

function parseLcov(content: string): Map<string, number> {
  const map = new Map<string, number>();
  let currentFile = "";
  let found = 0;
  let hit = 0;
  for (const raw of content.split(/\r?\n/)) {
    const line = raw.trim();
    if (line.startsWith("SF:")) {
      currentFile = line.slice(3).replace(/\\/g, "/");
      found = 0;
      hit = 0;
    } else if (line.startsWith("DA:")) {
      const parts = line.slice(3).split(",");
      found += 1;
      if (Number(parts[1] ?? "0") > 0) hit += 1;
    } else if (line === "end_of_record" && currentFile) {
      map.set(currentFile, found > 0 ? hit / found : 1);
      currentFile = "";
    }
  }
  return map;
}

function parseCoberturaXml(content: string): Map<string, number> {
  const map = new Map<string, number>();
  const classRe = /<class\b[^>]*filename="([^"]+)"[^>]*line-rate="([0-9.]+)"/gi;
  for (const m of content.matchAll(classRe)) {
    const file = (m[1] ?? "").replace(/\\/g, "/");
    const rate = Number(m[2] ?? "0");
    if (file && Number.isFinite(rate)) map.set(file, Math.max(0, Math.min(1, rate)));
  }
  return map;
}

function parseStrykerJson(content: string): number | undefined {
  try {
    const parsed = JSON.parse(content) as {
      files?: Record<string, { mutants?: Array<{ status?: string }> }>;
    };
    if (!parsed.files || typeof parsed.files !== "object") return undefined;
    let detected = 0;
    let undetected = 0;
    for (const file of Object.values(parsed.files)) {
      for (const mut of file.mutants ?? []) {
        const st = (mut.status ?? "").toLowerCase();
        if (st === "killed" || st === "timeout") detected += 1;
        else if (st === "survived" || st === "nocoverage") undetected += 1;
      }
    }
    const denom = detected + undetected;
    if (denom === 0) return undefined;
    return Number(((detected / denom) * 100).toFixed(2));
  } catch {
    return undefined;
  }
}

function parseJunitOrTrx(content: string): { passed: number; failed: number; skipped: number } | undefined {
  const trxMatch = /<Counters\b[^>]*total="(\d+)"[^>]*passed="(\d+)"[^>]*failed="(\d+)"/i.exec(content);
  if (trxMatch) {
    const total = Number(trxMatch[1] ?? "0");
    const passed = Number(trxMatch[2] ?? "0");
    const failed = Number(trxMatch[3] ?? "0");
    return { passed, failed, skipped: Math.max(0, total - passed - failed) };
  }
  const junitMatch = /<testsuites?\b[^>]*tests="(\d+)"/i.exec(content);
  if (junitMatch) {
    const total = Number(junitMatch[1] ?? "0");
    const failMatch = /failures="(\d+)"/i.exec(content);
    const errMatch = /errors="(\d+)"/i.exec(content);
    const skipMatch = /skipped="(\d+)"/i.exec(content);
    const failed = Number(failMatch?.[1] ?? "0") + Number(errMatch?.[1] ?? "0");
    const skipped = Number(skipMatch?.[1] ?? "0");
    return { passed: Math.max(0, total - failed - skipped), failed, skipped };
  }
  return undefined;
}

export function parseStructuredReports(repoRoot: string): StructuredReportMetrics {
  const result: StructuredReportMetrics = { fileCoverage: new Map() };
  const lcovPaths = ["coverage/lcov.info", "lcov.info", ".verification/lcov.info"];
  for (const rel of lcovPaths) {
    const abs = path.join(repoRoot, rel);
    if (fs.existsSync(abs)) {
      result.fileCoverage = parseLcov(fs.readFileSync(abs, "utf8"));
      break;
    }
  }
  if (result.fileCoverage.size === 0) {
    for (const rel of ["coverage/cobertura-coverage.xml", "coverage.cobertura.xml", ".verification/coverage.cobertura.xml"]) {
      const abs = path.join(repoRoot, rel);
      if (fs.existsSync(abs)) {
        result.fileCoverage = parseCoberturaXml(fs.readFileSync(abs, "utf8"));
        break;
      }
    }
  }
  if (result.fileCoverage.size > 0) {
    const vals = [...result.fileCoverage.values()];
    result.lineCoveragePct = Number(((vals.reduce((a, b) => a + b, 0) / vals.length) * 100).toFixed(2));
  }

  for (const rel of ["reports/mutation/mutation.json", "StrykerOutput/mutation-report.json", ".verification/mutation.json"]) {
    const abs = path.join(repoRoot, rel);
    if (fs.existsSync(abs)) {
      const score = parseStrykerJson(fs.readFileSync(abs, "utf8"));
      if (score !== undefined) {
        result.mutationScore = score;
        break;
      }
    }
  }

  for (const rel of ["junit.xml", "test-results/junit.xml", "TestResults/results.trx", ".verification/junit.xml"]) {
    const abs = path.join(repoRoot, rel);
    if (fs.existsSync(abs)) {
      const counts = parseJunitOrTrx(fs.readFileSync(abs, "utf8"));
      if (counts) {
        result.testsPassed = counts.passed;
        result.testsFailed = counts.failed;
        result.testsSkipped = counts.skipped;
        break;
      }
    }
  }
  return result;
}

function estimateCyclomaticComplexity(source: string): number {
  const branches = source.match(/\b(?:if|else\s+if|for|while|case|catch)\b|\?\?|\?[^:]|&&|\|\|/g);
  return 1 + (branches ? branches.length : 0);
}

export function computeCrapScore(cyclomaticComplexity: number, coverageFraction: number): number {
  const cov = Math.max(0, Math.min(1, coverageFraction));
  const cc = Math.max(1, cyclomaticComplexity);
  return Number((cc * cc * Math.pow(1 - cov, 3) + cc).toFixed(2));
}

export function evaluateCrapForCoverageFile(
  repoRoot: string,
  coveragePath: string,
  maxAllowed = 30,
): CrapReport {
  const absCov = path.isAbsolute(coveragePath) ? coveragePath : path.join(repoRoot, coveragePath);
  const raw = fs.readFileSync(absCov, "utf8");
  const covMap = raw.trimStart().startsWith("<") ? parseCoberturaXml(raw) : parseLcov(raw);
  const offenders: CrapEntry[] = [];
  let worstCrap = 0;
  let evaluatedFiles = 0;

  for (const [fileRel, covFrac] of covMap.entries()) {
    const absFile = path.isAbsolute(fileRel) ? fileRel : path.join(repoRoot, fileRel);
    if (!fs.existsSync(absFile)) continue;
    evaluatedFiles += 1;
    const cc = estimateCyclomaticComplexity(fs.readFileSync(absFile, "utf8"));
    const score = computeCrapScore(cc, covFrac);
    if (score > worstCrap) worstCrap = score;
    if (score > maxAllowed) {
      offenders.push({
        file: path.relative(repoRoot, absFile).split(path.sep).join("/"),
        cyclomaticComplexity: cc,
        coveragePct: Number((covFrac * 100).toFixed(1)),
        crapScore: score,
      });
    }
  }

  offenders.sort((a, b) => b.crapScore - a.crapScore);
  return {
    maxAllowed,
    passed: evaluatedFiles > 0 && offenders.length === 0,
    worstCrap,
    offenders,
    evaluatedFiles,
  };
}

export const reportParsers = {
  parseLcov,
  parseCoberturaXml,
  parseStrykerJson,
  parseJunitOrTrx,
};
