import fs from "node:fs";
import path from "node:path";
import { parseSync } from "oxc-parser";
import { discoverRepo } from "../discover.ts";
import type { RungId } from "../types.ts";
import { isHostRepoFile } from "./manifest.ts";

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
  uncoveredRepoFiles: string[];
}

function parseLcov(content: string): Map<string, number> {
  const accum = new Map<string, { found: number; hit: number }>();
  let currentFile = "";
  let daFound = 0;
  let daHit = 0;
  let lf = -1;
  let lh = -1;

  for (const raw of content.split(/\r?\n/)) {
    const line = raw.trim();
    if (line.startsWith("SF:")) {
      currentFile = line.slice(3).replace(/\\/g, "/");
      daFound = 0;
      daHit = 0;
      lf = -1;
      lh = -1;
    } else if (line.startsWith("DA:")) {
      const parts = line.slice(3).split(",");
      daFound += 1;
      if (Number(parts[1] ?? "0") > 0) daHit += 1;
    } else if (line.startsWith("LF:")) {
      lf = Number(line.slice(3));
    } else if (line.startsWith("LH:")) {
      lh = Number(line.slice(3));
    } else if (line === "end_of_record" && currentFile) {
      const found = daFound > 0 ? daFound : lf > 0 ? lf : 0;
      const hit = daFound > 0 ? daHit : lh >= 0 ? lh : 0;
      const prev = accum.get(currentFile) ?? { found: 0, hit: 0 };
      accum.set(currentFile, { found: prev.found + found, hit: prev.hit + hit });
      currentFile = "";
    }
  }

  const map = new Map<string, number>();
  for (const [file, { found, hit }] of accum.entries()) {
    map.set(file, found > 0 ? Math.max(0, Math.min(1, hit / found)) : 0);
  }
  return map;
}

function readXmlAttr(attrs: string, name: string): string | undefined {
  const target = name.toLowerCase();
  for (const m of attrs.matchAll(/\b([a-zA-Z0-9_:-]+)\s*=\s*"([^"]*)"/g)) {
    if ((m[1] ?? "").toLowerCase() === target) return m[2];
  }
  return undefined;
}

function parseCoberturaXml(content: string): Map<string, number> {
  const map = new Map<string, number>();
  for (const m of content.matchAll(/<class\b([^>]*?)>/gi)) {
    const attrs = m[1] ?? "";
    const file = (readXmlAttr(attrs, "filename") ?? "").replace(/\\/g, "/");
    const rateRaw = readXmlAttr(attrs, "line-rate");
    const rate = rateRaw !== undefined ? Number(rateRaw) : Number.NaN;
    if (!file || !Number.isFinite(rate)) continue;
    const clamped = Math.max(0, Math.min(1, rate));
    const prev = map.get(file);
    map.set(file, prev === undefined ? clamped : Math.min(prev, clamped));
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
  const trxMatch = /<Counters\b([^>]*?)>/i.exec(content);
  if (trxMatch?.[1]) {
    const attrs = trxMatch[1];
    const total = Number(readXmlAttr(attrs, "total") ?? "NaN");
    const passed = Number(readXmlAttr(attrs, "passed") ?? "0");
    const failed =
      Number(readXmlAttr(attrs, "failed") ?? "0") +
      Number(readXmlAttr(attrs, "error") ?? "0") +
      Number(readXmlAttr(attrs, "timeout") ?? "0") +
      Number(readXmlAttr(attrs, "aborted") ?? "0");
    if (Number.isFinite(total)) {
      return { passed, failed, skipped: Math.max(0, total - passed - failed) };
    }
  }

  const suites = [...content.matchAll(/<testsuite\b([^>]*?)>/gi)];
  if (suites.length > 0) {
    let total = 0;
    let failed = 0;
    let skipped = 0;
    let matchedAny = false;
    for (const s of suites) {
      const attrs = s[1] ?? "";
      const t = Number(readXmlAttr(attrs, "tests") ?? "NaN");
      if (!Number.isFinite(t)) continue;
      matchedAny = true;
      total += t;
      failed += Number(readXmlAttr(attrs, "failures") ?? "0") + Number(readXmlAttr(attrs, "errors") ?? "0");
      skipped += Number(readXmlAttr(attrs, "skipped") ?? "0");
    }
    if (matchedAny) {
      return { passed: Math.max(0, total - failed - skipped), failed, skipped };
    }
  }

  const rootMatch = /<testsuites\b([^>]*?)>/i.exec(content);
  if (rootMatch?.[1]) {
    const attrs = rootMatch[1];
    const total = Number(readXmlAttr(attrs, "tests") ?? "NaN");
    if (Number.isFinite(total)) {
      const failed = Number(readXmlAttr(attrs, "failures") ?? "0") + Number(readXmlAttr(attrs, "errors") ?? "0");
      const skipped = Number(readXmlAttr(attrs, "skipped") ?? "0");
      return { passed: Math.max(0, total - failed - skipped), failed, skipped };
    }
  }
  return undefined;
}

function isFreshFile(abs: string, minMtimeMs?: number): boolean {
  if (!fs.existsSync(abs)) return false;
  if (minMtimeMs === undefined) return true;
  try {
    return fs.statSync(abs).mtimeMs >= minMtimeMs;
  } catch {
    return false;
  }
}

export function parseStructuredReports(
  repoRoot: string,
  options?: { minMtimeMs?: number; rung?: RungId },
): StructuredReportMetrics {
  const result: StructuredReportMetrics = { fileCoverage: new Map() };
  const minMtimeMs = options?.minMtimeMs;
  const rung = options?.rung;

  for (const rel of ["coverage/lcov.info", "lcov.info", ".verification/lcov.info"]) {
    const abs = path.join(repoRoot, rel);
    if (isFreshFile(abs, minMtimeMs)) {
      result.fileCoverage = parseLcov(fs.readFileSync(abs, "utf8"));
      break;
    }
  }
  if (result.fileCoverage.size === 0) {
    for (const rel of ["coverage/cobertura-coverage.xml", "coverage.cobertura.xml", ".verification/coverage.cobertura.xml"]) {
      const abs = path.join(repoRoot, rel);
      if (isFreshFile(abs, minMtimeMs)) {
        result.fileCoverage = parseCoberturaXml(fs.readFileSync(abs, "utf8"));
        break;
      }
    }
  }
  if (result.fileCoverage.size > 0) {
    const vals = [...result.fileCoverage.values()];
    result.lineCoveragePct = Number(((vals.reduce((a, b) => a + b, 0) / vals.length) * 100).toFixed(2));
  }

  if (!rung || rung === "R5") {
    for (const rel of ["reports/mutation/mutation.json", "StrykerOutput/mutation-report.json", ".verification/mutation.json"]) {
      const abs = path.join(repoRoot, rel);
      if (isFreshFile(abs, minMtimeMs)) {
        const score = parseStrykerJson(fs.readFileSync(abs, "utf8"));
        if (score !== undefined) {
          result.mutationScore = score;
          break;
        }
      }
    }
  }

  if (!rung || rung === "R2" || rung === "R3" || rung === "R4") {
    for (const rel of ["junit.xml", "test-results/junit.xml", "TestResults/results.trx", ".verification/junit.xml"]) {
      const abs = path.join(repoRoot, rel);
      if (isFreshFile(abs, minMtimeMs)) {
        const counts = parseJunitOrTrx(fs.readFileSync(abs, "utf8"));
        if (counts) {
          result.testsPassed = counts.passed;
          result.testsFailed = counts.failed;
          result.testsSkipped = counts.skipped;
          break;
        }
      }
    }
  }
  return result;
}

const JS_BRANCH_TYPES = new Set([
  "IfStatement",
  "ForStatement",
  "ForInStatement",
  "ForOfStatement",
  "WhileStatement",
  "DoWhileStatement",
  "CatchClause",
  "ConditionalExpression",
  "LogicalExpression",
]);

const JS_FUNC_TYPES = new Set(["FunctionDeclaration", "FunctionExpression", "ArrowFunctionExpression"]);

function maxJsFunctionCc(filePath: string, source: string): number {
  try {
    const parsed = parseSync(filePath, source);
    let maxCc = 1;
    const walk = (node: unknown, curFuncBranches: { count: number }): void => {
      if (!node || typeof node !== "object") return;
      const rec = node as Record<string, unknown>;
      const t = typeof rec.type === "string" ? rec.type : "";
      if (JS_FUNC_TYPES.has(t)) {
        const childCounter = { count: 1 };
        for (const val of Object.values(rec)) {
          if (Array.isArray(val)) for (const item of val) walk(item, childCounter);
          else if (val && typeof val === "object") walk(val, childCounter);
        }
        if (childCounter.count > maxCc) maxCc = childCounter.count;
        return;
      }
      if (JS_BRANCH_TYPES.has(t) || (t === "SwitchCase" && rec.test !== null)) {
        curFuncBranches.count += 1;
      }
      for (const val of Object.values(rec)) {
        if (Array.isArray(val)) for (const item of val) walk(item, curFuncBranches);
        else if (val && typeof val === "object") walk(val, curFuncBranches);
      }
    };
    const topLevel = { count: 1 };
    walk(parsed.program, topLevel);
    return Math.max(maxCc, topLevel.count);
  } catch {
    return 1;
  }
}

function stripNonCode(source: string): string {
  return source
    .replace(/"""[\s\S]*?"""|'''[\s\S]*?'''/g, " ")
    .replace(/\/\*[\s\S]*?\*\//g, " ")
    .replace(/(^|[^:\\])\/\/[^\n]*/g, "$1 ")
    .replace(/(^|\s)#[^\n]*/g, "$1 ")
    .replace(/"(?:\\.|[^"\\])*"/g, '""')
    .replace(/'(?:\\.|[^'\\])*'/g, "''");
}

function estimateMaxFunctionCc(filePath: string, source: string): number {
  if (/\.[cm]?[jt]sx?$/.test(filePath)) return maxJsFunctionCc(filePath, source);
  const cleaned = stripNonCode(source);
  const chunks = cleaned.split(/\n(?=(?:def |async def |pub\s+fn |fn |func ))/);
  let maxCc = 1;
  for (const chunk of chunks) {
    const branches = chunk.match(/\b(?:if|elif|else\s+if|for|while|case|catch|except|and|or)\b|&&|\|\||=>|\?(?![.?])/g);
    const cc = 1 + (branches ? branches.length : 0);
    if (cc > maxCc) maxCc = cc;
  }
  return maxCc;
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
  if (!Number.isFinite(maxAllowed) || maxAllowed <= 0) {
    throw new Error(`Invalid --max-crap threshold '${String(maxAllowed)}'; must be a positive finite number.`);
  }
  const absRoot = path.resolve(repoRoot);
  const absCov = path.isAbsolute(coveragePath) ? coveragePath : path.join(absRoot, coveragePath);
  const raw = fs.readFileSync(absCov, "utf8");
  const covMap = raw.trimStart().startsWith("<") ? parseCoberturaXml(raw) : parseLcov(raw);
  const offenders: CrapEntry[] = [];
  const coveredRelSet = new Set<string>();
  let worstCrap = 0;
  let evaluatedFiles = 0;

  for (const [fileRel, covFrac] of covMap.entries()) {
    const absFile = path.resolve(absRoot, fileRel);
    if (absFile !== absRoot && !absFile.startsWith(`${absRoot}${path.sep}`)) continue;
    if (!fs.existsSync(absFile) || !fs.statSync(absFile).isFile()) continue;
    const normRel = path.relative(absRoot, absFile).split(path.sep).join("/");
    coveredRelSet.add(normRel);
    evaluatedFiles += 1;
    const cc = estimateMaxFunctionCc(absFile, fs.readFileSync(absFile, "utf8"));
    const score = computeCrapScore(cc, covFrac);
    if (score > worstCrap) worstCrap = score;
    if (score > maxAllowed) {
      offenders.push({
        file: normRel,
        cyclomaticComplexity: cc,
        coveragePct: Number((covFrac * 100).toFixed(1)),
        crapScore: score,
      });
    }
  }

  const repo = discoverRepo(absRoot);
  const uncoveredRepoFiles = repo.files
    .filter((f) => f.language && !f.isTest && isHostRepoFile(f.rel) && !coveredRelSet.has(f.rel))
    .map((f) => f.rel)
    .sort();

  offenders.sort((a, b) => b.crapScore - a.crapScore);
  return {
    maxAllowed,
    passed: evaluatedFiles > 0 && offenders.length === 0 && uncoveredRepoFiles.length === 0,
    worstCrap,
    offenders,
    evaluatedFiles,
    uncoveredRepoFiles,
  };
}

export const reportParsers = {
  parseLcov,
  parseCoberturaXml,
  parseStrykerJson,
  parseJunitOrTrx,
};
