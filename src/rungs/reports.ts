import fs from "node:fs";
import path from "node:path";
import { parseSync } from "oxc-parser";
import { discoverRepo } from "../discover.ts";
import { maskCode } from "../test-lexical.ts";
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
interface CrapEntry { file: string; cyclomaticComplexity: number; coveragePct: number; crapScore: number; }
interface CrapReport {
  maxAllowed: number; passed: boolean; worstCrap: number;
  offenders: CrapEntry[]; evaluatedFiles: number; uncoveredRepoFiles: string[];
}
interface DetailedCoverage { fileRate: Map<string, number>; lineHits: Map<string, Map<number, number>>; }

const EXACT_REPORT_PATHS: ReadonlySet<string> = new Set([
  "coverage/lcov.info", "lcov.info", ".verification/lcov.info",
  "coverage/cobertura-coverage.xml", "coverage.cobertura.xml", ".verification/coverage.cobertura.xml",
  "reports/mutation/mutation.json", "StrykerOutput/mutation-report.json", ".verification/mutation.json",
  "junit.xml", "test-results/junit.xml", "TestResults/results.trx",
  ".verification/junit.xml", ".verification/reports/junit.xml",
]);

function parseLcovDetailed(content: string): DetailedCoverage {
  const accum = new Map<string, { found: number; hit: number }>();
  const lineHits = new Map<string, Map<number, number>>();
  let currentFile = ""; let daFound = 0; let daHit = 0; let lf = -1; let lh = -1;

  for (const raw of content.split(/\r?\n/)) {
    const line = raw.trim();
    if (line.startsWith("SF:")) {
      currentFile = line.slice(3).replace(/\\/g, "/");
      daFound = 0; daHit = 0; lf = -1; lh = -1;
    } else if (line.startsWith("DA:") && currentFile) {
      const parts = line.slice(3).split(",");
      const lineNo = Number(parts[0] ?? "0"); const hits = Number(parts[1] ?? "0");
      daFound += 1; if (hits > 0) daHit += 1;
      if (Number.isFinite(lineNo) && lineNo > 0) {
        const fmap = lineHits.get(currentFile) ?? new Map<number, number>();
        fmap.set(lineNo, (fmap.get(lineNo) ?? 0) + (Number.isFinite(hits) ? hits : 0));
        lineHits.set(currentFile, fmap);
      }
    } else if (line.startsWith("LF:")) lf = Number(line.slice(3));
    else if (line.startsWith("LH:")) lh = Number(line.slice(3));
    else if (line === "end_of_record" && currentFile) {
      const found = daFound > 0 ? daFound : lf > 0 ? lf : 0;
      const hit = daFound > 0 ? daHit : lh >= 0 ? lh : 0;
      const prev = accum.get(currentFile) ?? { found: 0, hit: 0 };
      accum.set(currentFile, { found: prev.found + found, hit: prev.hit + hit });
      currentFile = "";
    }
  }
  const fileRate = new Map<string, number>();
  for (const [file, { found, hit }] of accum.entries()) fileRate.set(file, found > 0 ? Math.max(0, Math.min(1, hit / found)) : 0);
  return { fileRate, lineHits };
}

function parseLcov(content: string): Map<string, number> {
  return parseLcovDetailed(content).fileRate;
}

function readXmlAttr(attrs: string, name: string): string | undefined {
  const target = name.toLowerCase();
  for (const m of attrs.matchAll(/\b([a-zA-Z0-9_:-]+)\s*=\s*(?:"([^"]*)"|'([^']*)')/g)) {
    if ((m[1] ?? "").toLowerCase() === target) return m[2] ?? m[3];
  }
  return undefined;
}

function stripXmlNonStructure(xml: string): string {
  return xml
    .replace(/<!\[CDATA\[[\s\S]*?\]\]>/g, "")
    .replace(/<!--[\s\S]*?-->/g, "")
    .replace(/<system-(?:out|err)\b[^>]*>[\s\S]*?<\/system-(?:out|err)>/gi, "");
}

function parseCoberturaDetailed(content: string, repoRoot?: string): DetailedCoverage {
  const cleaned = stripXmlNonStructure(content);
  const fileRate = new Map<string, number>();
  const lineHits = new Map<string, Map<number, number>>();
  const sources: string[] = [];
  for (const sm of cleaned.matchAll(/<source>\s*([^<]+?)\s*<\/source>/gi)) {
    if (sm[1]) sources.push(sm[1].trim().replace(/\\/g, "/"));
  }
  const resolveFile = (rawFile: string): string => {
    const clean = rawFile.replace(/\\/g, "/");
    if (!repoRoot) return clean;
    if (fs.existsSync(path.resolve(repoRoot, clean))) return clean;
    for (const src of sources) {
      const joined = path.resolve(src, clean);
      if (fs.existsSync(joined)) return path.relative(repoRoot, joined).split(path.sep).join("/");
    }
    return clean;
  };

  for (const m of cleaned.matchAll(/<class\b([^>]*?)>([\s\S]*?)<\/class>|<class\b([^>]*?)\/>/gi)) {
    const attrs = m[1] ?? m[3] ?? "";
    const body = m[2] ?? "";
    const rawFile = readXmlAttr(attrs, "filename") ?? "";
    if (!rawFile) continue;
    const file = resolveFile(rawFile);
    let lineCount = 0;
    let lineHit = 0;
    for (const lm of body.matchAll(/<line\b([^>]*?)\/?>/gi)) {
      const la = lm[1] ?? "";
      const num = Number(readXmlAttr(la, "number") ?? "NaN");
      const hits = Number(readXmlAttr(la, "hits") ?? "NaN");
      if (Number.isFinite(num) && num > 0 && Number.isFinite(hits)) {
        lineCount += 1;
        if (hits > 0) lineHit += 1;
        const fmap = lineHits.get(file) ?? new Map<number, number>();
        fmap.set(num, (fmap.get(num) ?? 0) + hits);
        lineHits.set(file, fmap);
      }
    }
    const rateRaw = readXmlAttr(attrs, "line-rate");
    const attrRate = rateRaw !== undefined ? Number(rateRaw) : Number.NaN;
    const rate = lineCount > 0 ? lineHit / lineCount : attrRate;
    if (!Number.isFinite(rate)) continue;
    const clamped = Math.max(0, Math.min(1, rate));
    const prev = fileRate.get(file);
    fileRate.set(file, prev === undefined ? clamped : Math.min(prev, clamped));
  }
  return { fileRate, lineHits };
}

function parseCoberturaXml(content: string, repoRoot?: string): Map<string, number> {
  return parseCoberturaDetailed(content, repoRoot).fileRate;
}

function parseStrykerJson(content: string): number | undefined {
  try {
    const parsed = JSON.parse(content) as { files?: Record<string, { mutants?: Array<{ status?: string }> }> };
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
    return detected + undetected === 0 ? undefined : Number(((detected / (detected + undetected)) * 100).toFixed(2));
  } catch {
    return undefined;
  }
}

function parseIntAttr(attrs: string, name: string, required = false): number | null {
  const raw = readXmlAttr(attrs, name);
  if (raw === undefined) return required ? null : 0;
  if (!/^\d+$/.test(raw.trim())) return null;
  return Number(raw.trim());
}

function parseJunitOrTrx(content: string): { passed: number; failed: number; skipped: number } | undefined {
  const cleaned = stripXmlNonStructure(content);
  const isTrx = /<TestRun\b/i.test(cleaned) || (!/<testsuites?\b/i.test(cleaned) && /<Counters\b/i.test(cleaned));
  if (isTrx) {
    const trxMatch = /<Counters\b([^>]*?)\/?>/i.exec(cleaned);
    if (trxMatch?.[1]) {
      const a = trxMatch[1];
      const nums = [
        parseIntAttr(a, "total", true), parseIntAttr(a, "passed"), parseIntAttr(a, "failed"),
        parseIntAttr(a, "error"), parseIntAttr(a, "timeout"), parseIntAttr(a, "aborted"),
        parseIntAttr(a, "inconclusive"), parseIntAttr(a, "notRunnable"),
      ];
      if (nums.some((n) => n === null)) return undefined;
      const [total, passed, failed, err, timeout, aborted, inconclusive, notRunnable] = nums as number[];
      const totalFailed = (failed ?? 0) + (err ?? 0) + (timeout ?? 0) + (aborted ?? 0) + (inconclusive ?? 0) + (notRunnable ?? 0);
      return { passed: passed ?? 0, failed: totalFailed, skipped: Math.max(0, (total ?? 0) - (passed ?? 0) - totalFailed) };
    }
  }

  let depth = 0; let countedDepth = -1; let total = 0; let failed = 0; let skipped = 0;
  let matchedAny = false; let invalidAttr = false;

  for (const tag of cleaned.matchAll(/<(\/?)testsuite\b([^>]*?)(\/?)>/gi)) {
    const attrs = tag[2] ?? "";
    if (tag[1] === "/") {
      depth = Math.max(0, depth - 1);
      if (countedDepth === depth) countedDepth = -1;
      continue;
    }
    if (countedDepth < 0) {
      const t = parseIntAttr(attrs, "tests", true);
      const f = parseIntAttr(attrs, "failures");
      const e = parseIntAttr(attrs, "errors");
      const sk = parseIntAttr(attrs, "skipped");
      const dis = parseIntAttr(attrs, "disabled");
      if (t !== null) {
        if (f === null || e === null || sk === null || dis === null) { invalidAttr = true; break; }
        matchedAny = true;
        total += t;
        failed += f + e;
        skipped += sk + dis;
        if (tag[3] !== "/") countedDepth = depth;
      }
    }
    if (tag[3] !== "/") depth += 1;
  }

  if (invalidAttr) return undefined;
  if (matchedAny) return { passed: Math.max(0, total - failed - skipped), failed, skipped };

  const rootMatch = /<testsuites\b([^>]*?)>/i.exec(cleaned);
  if (rootMatch?.[1]) {
    const a = rootMatch[1];
    const t = parseIntAttr(a, "tests", true);
    const f = parseIntAttr(a, "failures");
    const e = parseIntAttr(a, "errors");
    const sk = parseIntAttr(a, "skipped");
    const dis = parseIntAttr(a, "disabled");
    if (t === null || f === null || e === null || sk === null || dis === null) return undefined;
    return { passed: Math.max(0, t - (f + e) - (sk + dis)), failed: f + e, skipped: sk + dis };
  }
  return undefined;
}

function isFreshFile(
  abs: string,
  rel: string,
  minMtimeMs?: number,
  maxMtimeMs?: number,
  preSnapshot?: ReadonlyMap<string, { mtimeMs: number; size: number }>,
): boolean {
  if (!fs.existsSync(abs)) return false;
  if (minMtimeMs === undefined && maxMtimeMs === undefined && !preSnapshot) return true;
  try {
    const st = fs.statSync(abs);
    if (preSnapshot) {
      const prev = preSnapshot.get(rel);
      if (!prev) return true;
      if (prev.mtimeMs !== st.mtimeMs || prev.size !== st.size) return true;
      return false;
    }
    const slackMin = minMtimeMs !== undefined ? minMtimeMs - 1500 : undefined;
    if (slackMin !== undefined && st.mtimeMs < slackMin) return false;
    if (maxMtimeMs !== undefined && st.mtimeMs > maxMtimeMs) return false;
    return true;
  } catch {
    return false;
  }
}

export function parseStructuredReports(
  repoRoot: string,
  options?: { minMtimeMs?: number; maxMtimeMs?: number; rung?: RungId; preSnapshot?: ReadonlyMap<string, { mtimeMs: number; size: number }> },
): StructuredReportMetrics {
  const result: StructuredReportMetrics = { fileCoverage: new Map() };
  const minM = options?.minMtimeMs;
  const maxM = options?.maxMtimeMs;
  const rung = options?.rung;
  const snap = options?.preSnapshot;

  for (const rel of ["coverage/lcov.info", "lcov.info", ".verification/lcov.info"]) {
    const abs = path.join(repoRoot, rel);
    if (isFreshFile(abs, rel, minM, maxM, snap)) {
      result.fileCoverage = parseLcov(fs.readFileSync(abs, "utf8"));
      break;
    }
  }
  if (result.fileCoverage.size === 0) {
    for (const rel of ["coverage/cobertura-coverage.xml", "coverage.cobertura.xml", ".verification/coverage.cobertura.xml"]) {
      const abs = path.join(repoRoot, rel);
      if (isFreshFile(abs, rel, minM, maxM, snap)) {
        result.fileCoverage = parseCoberturaXml(fs.readFileSync(abs, "utf8"), repoRoot);
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
      if (isFreshFile(abs, rel, minM, maxM, snap)) {
        const score = parseStrykerJson(fs.readFileSync(abs, "utf8"));
        if (score !== undefined) { result.mutationScore = score; break; }
      }
    }
  }

  if (!rung || rung === "R2" || rung === "R3" || rung === "R4") {
    for (const rel of ["junit.xml", "test-results/junit.xml", "TestResults/results.trx", ".verification/junit.xml", ".verification/reports/junit.xml"]) {
      const abs = path.join(repoRoot, rel);
      if (isFreshFile(abs, rel, minM, maxM, snap)) {
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
  "IfStatement", "ForStatement", "ForInStatement", "ForOfStatement",
  "WhileStatement", "DoWhileStatement", "CatchClause", "ConditionalExpression", "LogicalExpression",
]);
const JS_FUNC_TYPES = new Set(["FunctionDeclaration", "FunctionExpression", "ArrowFunctionExpression"]);
interface FunctionSpan { startLine: number; endLine: number; cc: number; }

function lineAtOffset(source: string, offset: number): number {
  let line = 1;
  for (let i = 0; i < offset && i < source.length; i++) if (source.charCodeAt(i) === 10) line += 1;
  return line;
}

function extractJsFunctionSpans(filePath: string, source: string): FunctionSpan[] {
  const totalLines = source.split(/\r?\n/).length;
  try {
    const parsed = parseSync(filePath, source);
    const spans: FunctionSpan[] = [];
    const walk = (node: unknown, cur: { count: number }): void => {
      if (!node || typeof node !== "object") return;
      const rec = node as Record<string, unknown>;
      const t = typeof rec.type === "string" ? rec.type : "";
      if (JS_FUNC_TYPES.has(t)) {
        const child = { count: 1 };
        for (const val of Object.values(rec)) {
          if (Array.isArray(val)) for (const item of val) walk(item, child);
          else if (val && typeof val === "object") walk(val, child);
        }
        const st = typeof rec.start === "number" ? lineAtOffset(source, rec.start) : 1;
        const en = typeof rec.end === "number" ? lineAtOffset(source, rec.end) : st;
        spans.push({ startLine: st, endLine: en, cc: child.count });
        return;
      }
      if (JS_BRANCH_TYPES.has(t) || (t === "SwitchCase" && rec.test !== null)) cur.count += 1;
      for (const val of Object.values(rec)) {
        if (Array.isArray(val)) for (const item of val) walk(item, cur);
        else if (val && typeof val === "object") walk(val, cur);
      }
    };
    const top = { count: 1 };
    walk(parsed.program, top);
    if (spans.length === 0 || top.count > 1) spans.push({ startLine: 1, endLine: totalLines, cc: top.count });
    return spans;
  } catch {
    return [{ startLine: 1, endLine: totalLines, cc: 1 }];
  }
}

function extractFallbackFunctionSpans(filePath: string, source: string): FunctionSpan[] {
  const lang = filePath.endsWith(".py") ? "python" : filePath.endsWith(".rs") ? "rust" : filePath.endsWith(".cs") ? "csharp" : filePath.endsWith(".go") ? "go" : undefined;
  const cleaned = maskCode(source, lang, true);
  const lines = cleaned.split(/\r?\n/);
  const isCs = lang === "csharp";
  const starts: number[] = [0];
  for (let i = 1; i < lines.length; i++) {
    const l = lines[i] ?? "";
    if (
      /^\s*(?:async\s+)?def\s+\w+\s*\(/.test(l) ||
      /^\s*(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?fn\s+\w+/.test(l) ||
      /^\s*func\s+(?:\([^)]+\)\s+)?\w+\s*\(/.test(l) ||
      (isCs && /^\s*(?:public|private|internal|protected)\s+(?:static\s+|async\s+|virtual\s+|override\s+)*[A-Za-z0-9_<>,.\s?]+\s+\w+\s*\(/.test(l))
    ) {
      starts.push(i);
    }
  }
  const branchRe = isCs
    ? /\b(?:if|else\s+if|for|foreach|while|case|catch)\b|&&|\|\|/g
    : /\b(?:if|elif|else\s+if|for|while|case|catch|except|and|or)\b|&&|\|\||=>|\?(?![.?])/g;
  const spans: FunctionSpan[] = [];
  for (let idx = 0; idx < starts.length; idx++) {
    const startIdx = starts[idx] ?? 0;
    const endIdx = (starts[idx + 1] ?? lines.length) - 1;
    const chunk = lines.slice(startIdx, endIdx + 1).join("\n");
    const branches = chunk.match(branchRe);
    spans.push({ startLine: startIdx + 1, endLine: endIdx + 1, cc: 1 + (branches ? branches.length : 0) });
  }
  return spans;
}

function computeOwnedSpanCoverage(
  spans: readonly FunctionSpan[],
  lineMap: ReadonlyMap<number, number> | undefined,
): Map<number, number> {
  const out = new Map<number, number>();
  if (!lineMap || lineMap.size === 0) {
    for (let i = 0; i < spans.length; i++) out.set(i, 0);
    return out;
  }
  const counts = spans.map(() => ({ found: 0, hit: 0 }));
  for (const [ln, hits] of lineMap.entries()) {
    let bestIdx = -1;
    let bestLen = Number.POSITIVE_INFINITY;
    for (let i = 0; i < spans.length; i++) {
      const sp = spans[i];
      if (!sp || ln < sp.startLine || ln > sp.endLine) continue;
      const len = sp.endLine - sp.startLine;
      if (len < bestLen) { bestLen = len; bestIdx = i; }
    }
    if (bestIdx >= 0) {
      const bucket = counts[bestIdx];
      if (bucket) { bucket.found += 1; if (hits > 0) bucket.hit += 1; }
    }
  }
  for (let i = 0; i < spans.length; i++) {
    const b = counts[i];
    out.set(i, b && b.found > 0 ? b.hit / b.found : 0);
  }
  return out;
}

export function computeCrapScore(cyclomaticComplexity: number, coverageFraction: number): number {
  const cov = Math.max(0, Math.min(1, coverageFraction));
  const cc = Math.max(1, cyclomaticComplexity);
  return Number((cc * cc * Math.pow(1 - cov, 3) + cc).toFixed(2));
}

export function evaluateCrapForCoverageFile(repoRoot: string, coveragePath: string, maxAllowed = 30): CrapReport {
  if (!Number.isFinite(maxAllowed) || maxAllowed <= 0) {
    throw new Error(`Invalid --max-crap threshold '${String(maxAllowed)}'; must be a positive finite number.`);
  }
  const absRoot = path.resolve(repoRoot);
  const absCov = path.isAbsolute(coveragePath) ? coveragePath : path.join(absRoot, coveragePath);
  const raw = fs.readFileSync(absCov, "utf8");
  const detailed = raw.trimStart().startsWith("<") ? parseCoberturaDetailed(raw, absRoot) : parseLcovDetailed(raw);
  const offenders: CrapEntry[] = [];
  const coveredRelSet = new Set<string>();
  let worstCrap = 0;
  let evaluatedFiles = 0;

  for (const [fileRel] of detailed.fileRate.entries()) {
    const absFile = path.resolve(absRoot, fileRel);
    if (absFile !== absRoot && !absFile.startsWith(`${absRoot}${path.sep}`)) continue;
    if (!fs.existsSync(absFile) || !fs.statSync(absFile).isFile()) continue;
    const normRel = path.relative(absRoot, absFile).split(path.sep).join("/");
    coveredRelSet.add(normRel);
    evaluatedFiles += 1;
    const source = fs.readFileSync(absFile, "utf8");
    const spans = /\.[cm]?[jt]sx?$/.test(absFile)
      ? extractJsFunctionSpans(absFile, source)
      : extractFallbackFunctionSpans(absFile, source);
    const ownedCov = computeOwnedSpanCoverage(spans, detailed.lineHits.get(fileRel));
    let fileWorstCrap = 0;
    let fileWorstCc = 1;
    let fileWorstCov = 1;
    for (let i = 0; i < spans.length; i++) {
      const span = spans[i];
      if (!span) continue;
      const cov = ownedCov.get(i) ?? 0;
      const score = computeCrapScore(span.cc, cov);
      if (score > fileWorstCrap) {
        fileWorstCrap = score;
        fileWorstCc = span.cc;
        fileWorstCov = cov;
      }
    }
    if (fileWorstCrap > worstCrap) worstCrap = fileWorstCrap;
    if (fileWorstCrap > maxAllowed) {
      offenders.push({ file: normRel, cyclomaticComplexity: fileWorstCc, coveragePct: Number((fileWorstCov * 100).toFixed(1)), crapScore: fileWorstCrap });
    }
  }

  const repo = discoverRepo(absRoot);
  const uncoveredRepoFiles = repo.files
    .filter((f) => f.language && !f.isTest && !f.rel.endsWith(".d.ts") && !f.rel.endsWith(".pyi") && isHostRepoFile(f.rel) && !coveredRelSet.has(f.rel))
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

export const reportParsers = { parseLcov, parseCoberturaXml, parseStrykerJson, parseJunitOrTrx, EXACT_REPORT_PATHS };
