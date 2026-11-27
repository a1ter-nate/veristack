import fs from "node:fs";
import path from "node:path";
import { parseSync } from "oxc-parser";
import { discoverRepo } from "../discover.ts";
import { maskCode } from "../test-lexical.ts";
import type { RungId } from "../types.ts";
import { isHostRepoFile } from "./manifest.ts";

interface StructuredReportMetrics { testsPassed?: number; testsFailed?: number; testsSkipped?: number; mutationScore?: number; lineCoveragePct?: number; fileCoverage: Map<string, number>; }
interface CrapEntry { file: string; cyclomaticComplexity: number; coveragePct: number; crapScore: number; }
interface CrapReport { maxAllowed: number; passed: boolean; worstCrap: number; offenders: CrapEntry[]; evaluatedFiles: number; uncoveredRepoFiles: string[]; }
interface DetailedCoverage { fileRate: Map<string, number>; lineHits: Map<string, Map<number, number>>; branchHits?: Map<string, Map<number, { found: number; hit: number }>>; }

const EXACT_REPORT_PATHS: ReadonlySet<string> = new Set([
  "coverage/lcov.info", "lcov.info", ".verification/lcov.info", "coverage/cobertura-coverage.xml", "coverage.cobertura.xml", ".verification/coverage.cobertura.xml",
  "reports/mutation/mutation.json", "StrykerOutput/mutation-report.json", ".verification/mutation.json",
  "junit.xml", "test-results/junit.xml", "TestResults/results.trx", ".verification/junit.xml", ".verification/reports/junit.xml",
]);

function realpathSafe(p: string): string {
  try { return fs.realpathSync(p); } catch {
    const parent = path.dirname(p);
    if (parent !== p) { try { return path.join(fs.realpathSync(parent), path.basename(p)); } catch { return path.resolve(p); } }
    return path.resolve(p);
  }
}

function canonicalizeCovPath(rawPath: string, repoRoot?: string): string {
  const clean = rawPath.replace(/\\/g, "/").replace(/^\.\//, "");
  if (!repoRoot) return clean;
  const realRoot = realpathSafe(repoRoot);
  const resolved = realpathSafe(path.resolve(realRoot, clean));
  if (resolved === realRoot || resolved.startsWith(`${realRoot}${path.sep}`)) {
    return path.relative(realRoot, resolved).split(path.sep).join("/");
  }
  return clean;
}

function parseLcovDetailed(content: string, repoRoot?: string): DetailedCoverage {
  if (!content) return { fileRate: new Map(), lineHits: new Map(), branchHits: new Map() };
  if (!content.trim()) return { fileRate: new Map(), lineHits: new Map(), branchHits: new Map() };
  const accum = new Map<string, { found: number; hit: number }>();
  const lineHits = new Map<string, Map<number, number>>();
  const branchHits = new Map<string, Map<number, { found: number; hit: number }>>();
  let currentFile = ""; let daFound = 0; let daHit = 0; let lf = -1; let lh = -1;
  for (const raw of content.split(/\r?\n/)) {
    const line = raw.trim();
    if (line.startsWith("SF:")) { currentFile = canonicalizeCovPath(line.slice(3), repoRoot); daFound = 0; daHit = 0; lf = -1; lh = -1; }
    else if (line.startsWith("DA:") && currentFile) {
      const [lnRaw, hitsRaw] = line.slice(3).split(",");
      const lineNo = Number(lnRaw ?? "0"); const hits = Number(hitsRaw ?? "0");
      daFound += 1; if (hits > 0) daHit += 1;
      if (Number.isFinite(lineNo) && lineNo > 0) {
        const fmap = lineHits.get(currentFile) ?? new Map<number, number>();
        fmap.set(lineNo, (fmap.get(lineNo) ?? 0) + (Number.isFinite(hits) ? hits : 0));
        lineHits.set(currentFile, fmap);
      }
    } else if (line.startsWith("BRDA:") && currentFile) {
      const parts = line.slice(5).split(",");
      const lineNo = Number(parts[0] ?? "0"); const takenRaw = (parts[3] ?? "").trim(); const taken = takenRaw === "-" ? 0 : Number(takenRaw);
      if (Number.isFinite(lineNo) && lineNo > 0 && Number.isFinite(taken)) {
        const bmap = branchHits.get(currentFile) ?? new Map<number, { found: number; hit: number }>();
        const cur = bmap.get(lineNo) ?? { found: 0, hit: 0 };
        cur.found += 1; if (taken > 0) cur.hit += 1;
        bmap.set(lineNo, cur); branchHits.set(currentFile, bmap);
      }
    } else if (line.startsWith("LF:")) lf = Number(line.slice(3));
    else if (line.startsWith("LH:")) lh = Number(line.slice(3));
    else if (line === "end_of_record" && currentFile) {
      const found = daFound > 0 ? daFound : lf > 0 ? lf : 0; const hit = daFound > 0 ? daHit : lh >= 0 ? lh : 0;
      const prev = accum.get(currentFile) ?? { found: 0, hit: 0 };
      accum.set(currentFile, { found: prev.found + found, hit: prev.hit + hit });
      currentFile = "";
    }
  }
  const fileRate = new Map<string, number>();
  for (const [file, { found, hit }] of accum.entries()) fileRate.set(file, found > 0 ? Math.max(0, Math.min(1, hit / found)) : 0);
  return { fileRate, lineHits, branchHits };
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
  const branchHits = new Map<string, Map<number, { found: number; hit: number }>>();
  const sources: string[] = [];
  for (const sm of cleaned.matchAll(/<source>\s*([^<]+?)\s*<\/source>/gi)) {
    if (sm[1]) sources.push(sm[1].trim().replace(/\\/g, "/"));
  }
  const realRoot = repoRoot ? realpathSafe(repoRoot) : undefined;
  const resolveFile = (rawFile: string): string => {
    const clean = rawFile.replace(/\\/g, "/");
    if (!realRoot) return clean;
    const direct = realpathSafe(path.resolve(realRoot, clean));
    if (fs.existsSync(direct) && (direct === realRoot || direct.startsWith(`${realRoot}${path.sep}`))) {
      return path.relative(realRoot, direct).split(path.sep).join("/");
    }
    for (const src of sources) {
      const joined = realpathSafe(path.resolve(realRoot, src, clean));
      if (fs.existsSync(joined) && (joined === realRoot || joined.startsWith(`${realRoot}${path.sep}`))) {
        return path.relative(realRoot, joined).split(path.sep).join("/");
      }
    }
    return clean;
  };

  const classTags = scanXmlTags(cleaned, "class");
  for (let ti = 0; ti < classTags.length; ti++) {
    const tag = classTags[ti];
    if (!tag || tag.closing) continue;
    let body = "";
    if (!tag.selfClosing) {
      let d = 1;
      for (let tj = ti + 1; tj < classTags.length; tj++) {
        const nextTag = classTags[tj];
        if (!nextTag) continue;
        if (nextTag.closing) d -= 1;
        else if (!nextTag.selfClosing) d += 1;
        if (d === 0) { body = cleaned.slice(tag.end, nextTag.start); ti = tj; break; }
      }
    }
    const rawFile = readXmlAttr(tag.attrs, "filename") ?? "";
    if (!rawFile) continue;
    const file = resolveFile(rawFile);
    let lineCount = 0; let lineHit = 0;
    for (const ltag of scanXmlTags(body, "line")) {
      if (ltag.closing) continue;
      const num = Number(readXmlAttr(ltag.attrs, "number") ?? "NaN"); const hits = Number(readXmlAttr(ltag.attrs, "hits") ?? "NaN");
      if (Number.isFinite(num) && num > 0 && Number.isFinite(hits)) {
        lineCount += 1; if (hits > 0) lineHit += 1;
        const fmap = lineHits.get(file) ?? new Map<number, number>();
        fmap.set(num, (fmap.get(num) ?? 0) + hits); lineHits.set(file, fmap);
        const cc = readXmlAttr(ltag.attrs, "condition-coverage");
        const cm = cc ? /\((\d+)\/(\d+)\)/.exec(cc) : null;
        if (cm?.[1] && cm?.[2]) {
          const bmap = branchHits.get(file) ?? new Map<number, { found: number; hit: number }>();
          const cur = bmap.get(num) ?? { found: 0, hit: 0 };
          cur.hit += Number(cm[1]); cur.found += Number(cm[2]);
          bmap.set(num, cur); branchHits.set(file, bmap);
        }
      }
    }
    const rateRaw = readXmlAttr(tag.attrs, "line-rate");
    const rate = lineCount > 0 ? lineHit / lineCount : rateRaw !== undefined ? Number(rateRaw) : Number.NaN;
    if (!Number.isFinite(rate)) continue;
    const clamped = Math.max(0, Math.min(1, rate));
    const prev = fileRate.get(file);
    fileRate.set(file, prev === undefined ? clamped : Math.min(prev, clamped));
  }
  return { fileRate, lineHits, branchHits };
}

function parseCoberturaXml(content: string, repoRoot?: string): Map<string, number> {
  return parseCoberturaDetailed(content, repoRoot).fileRate;
}

function parseStrykerJson(content: string): number | undefined {
  try {
    const parsed = JSON.parse(content) as { files?: Record<string, { mutants?: Array<{ status?: string }> }> };
    if (!parsed.files || typeof parsed.files !== "object") return undefined;
    let detected = 0; let undetected = 0;
    for (const file of Object.values(parsed.files)) {
      for (const mut of file.mutants ?? []) {
        const st = (mut.status ?? "").toLowerCase();
        if (st === "killed" || st === "timeout") detected += 1;
        else if (st === "survived" || st === "nocoverage") undetected += 1;
      }
    }
    return detected + undetected === 0 ? undefined : Number(((detected / (detected + undetected)) * 100).toFixed(2));
  } catch { return undefined; }
}

function parseIntAttr(attrs: string, name: string, required = false): number | null {
  const raw = readXmlAttr(attrs, name);
  if (raw === undefined) return required ? null : 0;
  if (!/^\d+$/.test(raw.trim())) return null;
  return Number(raw.trim());
}

function scanXmlTags(xml: string, targetName: string): Array<{ closing: boolean; selfClosing: boolean; attrs: string; start: number; end: number }> {
  const out: Array<{ closing: boolean; selfClosing: boolean; attrs: string; start: number; end: number }> = [];
  const lowTarget = targetName.toLowerCase();
  for (let i = 0; i < xml.length; i++) {
    if (xml[i] !== "<") continue;
    let p = i + 1; const closing = xml[p] === "/"; if (closing) p += 1;
    const nameStart = p; while (p < xml.length && /[A-Za-z0-9_:-]/.test(xml[p] ?? "")) p += 1;
    if (xml.slice(nameStart, p).toLowerCase() !== lowTarget || (xml[p] !== undefined && !/[\s/>]/.test(xml[p] ?? ""))) continue;
    const attrStart = p; let q = ""; let end = -1;
    while (p < xml.length) {
      const ch = xml[p] ?? "";
      if (q) { if (ch === q) q = ""; p += 1; continue; }
      if (ch === '"' || ch === "'") { q = ch; p += 1; continue; }
      if (ch === ">") { end = p; break; }
      p += 1;
    }
    if (end < 0) break;
    const rawInside = xml.slice(attrStart, end).trim();
    const selfClosing = !closing && rawInside.endsWith("/");
    out.push({ closing, selfClosing, attrs: selfClosing ? rawInside.slice(0, -1) : rawInside, start: i, end: end + 1 });
    i = end;
  }
  return out;
}

function parseJunitOrTrx(content: string): { passed: number; failed: number; skipped: number } | undefined {
  const cleaned = stripXmlNonStructure(content);
  const isTrx = /<TestRun\b/i.test(cleaned) || (!/<testsuites?\b/i.test(cleaned) && /<Counters\b/i.test(cleaned));
  if (isTrx) {
    const trxTag = scanXmlTags(cleaned, "Counters")[0];
    if (trxTag) {
      const a = trxTag.attrs;
      const nums = [parseIntAttr(a, "total", true), parseIntAttr(a, "passed"), parseIntAttr(a, "failed"), parseIntAttr(a, "error"), parseIntAttr(a, "timeout"), parseIntAttr(a, "aborted"), parseIntAttr(a, "inconclusive"), parseIntAttr(a, "notRunnable")];
      if (nums.some((n) => n === null)) return undefined;
      const [total, passed, failed, err, timeout, aborted, inconclusive, notRunnable] = nums as number[];
      const totalFailed = (failed ?? 0) + (err ?? 0) + (timeout ?? 0) + (aborted ?? 0) + (inconclusive ?? 0) + (notRunnable ?? 0);
      return { passed: passed ?? 0, failed: totalFailed, skipped: Math.max(0, (total ?? 0) - (passed ?? 0) - totalFailed) };
    }
  }
  let depth = 0; let countedDepth = -1; let total = 0; let failed = 0; let skipped = 0; let matchedAny = false; let invalidAttr = false;
  let nestedFailed = 0;
  for (const tag of scanXmlTags(cleaned, "testsuite")) {
    if (tag.closing) { depth = Math.max(0, depth - 1); if (countedDepth === depth) countedDepth = -1; continue; }
    const [t, f, e, sk, dis] = [parseIntAttr(tag.attrs, "tests", true), parseIntAttr(tag.attrs, "failures"), parseIntAttr(tag.attrs, "errors"), parseIntAttr(tag.attrs, "skipped"), parseIntAttr(tag.attrs, "disabled")];
    if (t !== null && (f === null || e === null || sk === null || dis === null)) { invalidAttr = true; break; }
    if (countedDepth < 0) {
      if (t !== null) {
        matchedAny = true; total += t; failed += (f ?? 0) + (e ?? 0); skipped += (sk ?? 0) + (dis ?? 0);
        if (!tag.selfClosing && t > 0) countedDepth = depth;
      }
    } else if (t !== null && ((f ?? 0) + (e ?? 0)) > 0) {
      nestedFailed += (f ?? 0) + (e ?? 0);
    }
    if (!tag.selfClosing) depth += 1;
  }
  if (invalidAttr) return undefined;
  const effFailed = Math.max(failed, nestedFailed);
  if (matchedAny) return { passed: Math.max(0, total - effFailed - skipped), failed: effFailed, skipped };
  const rootTag = scanXmlTags(cleaned, "testsuites")[0];
  if (rootTag && !rootTag.closing) {
    const a = rootTag.attrs;
    const [t, f, e, sk, dis] = [parseIntAttr(a, "tests", true), parseIntAttr(a, "failures"), parseIntAttr(a, "errors"), parseIntAttr(a, "skipped"), parseIntAttr(a, "disabled")];
    if (t === null || f === null || e === null || sk === null || dis === null) return undefined;
    return { passed: Math.max(0, t - (f + e) - (sk + dis)), failed: f + e, skipped: sk + dis };
  }
  return undefined;
}

interface FreshFileOptions {
  minMtimeMs?: number;
  maxMtimeMs?: number;
  preSnapshot?: ReadonlyMap<string, { mtimeMs: number; size: number }>;
}

function isFreshFile(abs: string, rel: string, opts?: FreshFileOptions): boolean {
  let st: fs.Stats;
  try { st = fs.statSync(abs); } catch { return false; }
  const { minMtimeMs, maxMtimeMs, preSnapshot } = opts ?? {};
  if (minMtimeMs === undefined && maxMtimeMs === undefined && !preSnapshot) return true;
  if (preSnapshot) { const prev = preSnapshot.get(rel); return !prev || prev.mtimeMs !== st.mtimeMs || prev.size !== st.size; }
  if (minMtimeMs !== undefined && st.mtimeMs < minMtimeMs - 1500) return false;
  return maxMtimeMs === undefined || st.mtimeMs <= maxMtimeMs;
}

function parseStructuredReports(
  repoRoot: string,
  options?: { minMtimeMs?: number; maxMtimeMs?: number; rung?: RungId; preSnapshot?: ReadonlyMap<string, { mtimeMs: number; size: number }> },
): StructuredReportMetrics {
  if (!repoRoot) throw new Error("repoRoot is required.");
  const result: StructuredReportMetrics = { fileCoverage: new Map() };
  if (!fs.existsSync(repoRoot)) return result;
  const rung = options?.rung;
  for (const rel of ["coverage/lcov.info", "lcov.info", ".verification/lcov.info"]) {
    const abs = path.join(repoRoot, rel);
    if (isFreshFile(abs, rel, options)) { result.fileCoverage = parseLcov(fs.readFileSync(abs, "utf8")); break; }
  }
  if (result.fileCoverage.size === 0) {
    for (const rel of ["coverage/cobertura-coverage.xml", "coverage.cobertura.xml", ".verification/coverage.cobertura.xml"]) {
      const abs = path.join(repoRoot, rel);
      if (isFreshFile(abs, rel, options)) { result.fileCoverage = parseCoberturaXml(fs.readFileSync(abs, "utf8"), repoRoot); break; }
    }
  }
  if (result.fileCoverage.size > 0) {
    const vals = [...result.fileCoverage.values()];
    result.lineCoveragePct = Number(((vals.reduce((a, b) => a + b, 0) / vals.length) * 100).toFixed(2));
  }
  if (!rung || rung === "R5") {
    for (const rel of ["reports/mutation/mutation.json", "StrykerOutput/mutation-report.json", ".verification/mutation.json"]) {
      const abs = path.join(repoRoot, rel);
      if (isFreshFile(abs, rel, options)) { const score = parseStrykerJson(fs.readFileSync(abs, "utf8")); if (score !== undefined) { result.mutationScore = score; break; } }
    }
  }
  if (!rung || rung === "R2" || rung === "R3" || rung === "R4" || rung === "R7") {
    for (const rel of ["junit.xml", "test-results/junit.xml", "TestResults/results.trx", ".verification/junit.xml", ".verification/reports/junit.xml"]) {
      const abs = path.join(repoRoot, rel);
      if (isFreshFile(abs, rel, options)) {
        const counts = parseJunitOrTrx(fs.readFileSync(abs, "utf8"));
        if (counts) { result.testsPassed = counts.passed; result.testsFailed = counts.failed; result.testsSkipped = counts.skipped; break; }
      }
    }
  }
  return result;
}
export { parseStructuredReports };

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

function pushAstValueChildren(rec: Record<string, unknown>, target: { count: number }, stack: Array<{ node: unknown; cur: { count: number } }>): void {
  for (const val of Object.values(rec)) {
    if (Array.isArray(val)) for (let i = val.length - 1; i >= 0; i--) stack.push({ node: val[i], cur: target });
    else if (val && typeof val === "object") stack.push({ node: val, cur: target });
  }
}

function extractJsFunctionSpans(filePath: string, source: string): FunctionSpan[] {
  if (!filePath) throw new Error("filePath is required.");
  const totalLines = source.split(/\r?\n/).length;
  if (!source) return [{ startLine: 1, endLine: totalLines, cc: 1 }];
  let parsed: ReturnType<typeof parseSync>;
  try { parsed = parseSync(filePath, source); } catch { return [{ startLine: 1, endLine: totalLines, cc: 1 }]; }
  const pending: Array<{ startLine: number; endLine: number; counter: { count: number } }> = [];
  const top = { count: 1 };
  const stack: Array<{ node: unknown; cur: { count: number } }> = [{ node: parsed.program, cur: top }];
  while (stack.length > 0) {
    const frame = stack.pop();
    if (!frame || !frame.node || typeof frame.node !== "object") continue;
    const rec = frame.node as Record<string, unknown>;
    const t = typeof rec.type === "string" ? rec.type : "";
    let target = frame.cur;
    if (JS_FUNC_TYPES.has(t)) {
      target = { count: 1 };
      const st = typeof rec.start === "number" ? lineAtOffset(source, rec.start) : 1;
      const en = typeof rec.end === "number" ? lineAtOffset(source, rec.end) : st;
      pending.push({ startLine: st, endLine: en, counter: target });
    } else if (JS_BRANCH_TYPES.has(t) || (t === "SwitchCase" && rec.test !== null)) {
      target.count += 1;
    }
    pushAstValueChildren(rec, target, stack);
  }
  const spans: FunctionSpan[] = pending.map((p) => ({ startLine: p.startLine, endLine: p.endLine, cc: p.counter.count }));
  if (spans.length === 0 || top.count > 1) spans.push({ startLine: 1, endLine: totalLines, cc: top.count });
  return spans;
}

function extractFallbackFunctionSpans(filePath: string, source: string): FunctionSpan[] {
  if (!filePath) throw new Error("filePath is required.");
  if (!source) return [{ startLine: 1, endLine: 1, cc: 1 }];
  const lang = filePath.endsWith(".py") ? "python" : filePath.endsWith(".rs") ? "rust" : filePath.endsWith(".cs") ? "csharp" : filePath.endsWith(".go") ? "go" : undefined;
  const lines = maskCode(source, lang, true).split(/\r?\n/);
  const isCs = lang === "csharp";
  const starts: number[] = [0];
  for (let i = 1; i < lines.length; i++) {
    const l = lines[i] ?? "";
    if (/^\s*(?:async\s+)?def\s+\w+\s*\(/.test(l) || /^\s*(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?fn\s+\w+/.test(l) || /^\s*func\s+(?:\([^)]+\)\s+)?\w+\s*\(/.test(l) || (isCs && /^\s*(?:public|private|internal|protected)\s+(?:static\s+|async\s+|virtual\s+|override\s+)*[A-Za-z0-9_<>,.\s?]+\s+\w+\s*\(/.test(l))) starts.push(i);
  }
  const branchRe = isCs ? /\b(?:if|else\s+if|for|foreach|while|case|catch)\b|&&|\|\|/g : /\b(?:if|elif|else\s+if|for|while|case|catch|except|and|or)\b|&&|\|\||=>|\?(?![.?])/g;
  const spans: FunctionSpan[] = [];
  for (let idx = 0; idx < starts.length; idx++) {
    const startIdx = starts[idx] ?? 0; const endIdx = (starts[idx + 1] ?? lines.length) - 1;
    const branches = lines.slice(startIdx, endIdx + 1).join("\n").match(branchRe);
    spans.push({ startLine: startIdx + 1, endLine: endIdx + 1, cc: 1 + (branches ? branches.length : 0) });
  }
  return spans;
}

function attributeToInnermostSpans(spans: readonly FunctionSpan[], ln: number, onOwner: (idx: number) => void): void {
  let bestLen = Number.POSITIVE_INFINITY;
  for (let i = 0; i < spans.length; i++) { const sp = spans[i]; if (sp && ln >= sp.startLine && ln <= sp.endLine) bestLen = Math.min(bestLen, sp.endLine - sp.startLine); }
  if (!Number.isFinite(bestLen)) return;
  for (let i = 0; i < spans.length; i++) { const sp = spans[i]; if (sp && ln >= sp.startLine && ln <= sp.endLine && sp.endLine - sp.startLine === bestLen) onOwner(i); }
}

function fillUnattributedSpanLines(spans: readonly FunctionSpan[], idx: number, lineMap: ReadonlyMap<number, number>, bucket: { found: number; hit: number }): void {
  const sp = spans[idx]; if (!sp || bucket.found > 0) return;
  for (const [ln, hits] of lineMap.entries()) {
    if (ln < sp.startLine || ln > sp.endLine) continue;
    if (spans.every((o, j) => j === idx || ln < o.startLine || ln > o.endLine || o.startLine === o.endLine)) { bucket.found += 1; if (hits > 0) bucket.hit += 1; }
  }
}

function computeOwnedSpanCoverage(spans: readonly FunctionSpan[], lineMap: ReadonlyMap<number, number> | undefined, branchMap?: ReadonlyMap<number, { found: number; hit: number }>): Map<number, number> {
  const out = new Map<number, number>();
  if (spans.length === 0) return out;
  if (!lineMap || lineMap.size === 0) { for (let i = 0; i < spans.length; i++) out.set(i, 0); return out; }
  const counts = spans.map(() => ({ found: 0, hit: 0 }));
  const brCounts = spans.map(() => ({ found: 0, hit: 0 }));
  for (const [ln, hits] of lineMap.entries()) attributeToInnermostSpans(spans, ln, (i) => { const b = counts[i]; if (b) { b.found += 1; if (hits > 0) b.hit += 1; } });
  if (branchMap) for (const [ln, br] of branchMap.entries()) attributeToInnermostSpans(spans, ln, (i) => { const b = brCounts[i]; if (b) { b.found += br.found; b.hit += br.hit; } });
  for (let i = 0; i < spans.length; i++) {
    const b = counts[i]; if (b) fillUnattributedSpanLines(spans, i, lineMap, b);
    const lineCov = b && b.found > 0 ? b.hit / b.found : 0; const br = brCounts[i];
    out.set(i, Math.min(lineCov, br && br.found > 0 ? br.hit / br.found : lineCov));
  }
  return out;
}

export function computeCrapScore(cyclomaticComplexity: number, coverageFraction: number): number {
  const cov = Math.max(0, Math.min(1, coverageFraction));
  const cc = Math.max(1, cyclomaticComplexity);
  return Number((cc * cc * Math.pow(1 - cov, 3) + cc).toFixed(2));
}

export function evaluateCrapForCoverageFile(repoRoot: string, coveragePath: string, maxAllowed = 30): CrapReport {
  if (!Number.isFinite(maxAllowed) || maxAllowed <= 0) throw new Error(`Invalid --max-crap threshold '${String(maxAllowed)}'; must be a positive finite number.`);
  const absRoot = (() => { try { return fs.realpathSync(path.resolve(repoRoot)); } catch { return path.resolve(repoRoot); } })();
  const absCov = path.isAbsolute(coveragePath) ? coveragePath : path.join(absRoot, coveragePath);
  const raw = fs.readFileSync(absCov, "utf8");
  const detailed = raw.trimStart().startsWith("<") ? parseCoberturaDetailed(raw, absRoot) : parseLcovDetailed(raw, absRoot);
  const offenders: CrapEntry[] = [];
  const coveredRelSet = new Set<string>();
  let worstCrap = 0; let evaluatedFiles = 0;
  for (const [fileRel] of detailed.fileRate.entries()) {
    const absFile = path.resolve(absRoot, fileRel);
    if ((absFile !== absRoot && !absFile.startsWith(`${absRoot}${path.sep}`)) || !fs.existsSync(absFile) || !fs.statSync(absFile).isFile()) continue;
    coveredRelSet.add(path.relative(absRoot, absFile).split(path.sep).join("/"));
    evaluatedFiles += 1;
    const source = fs.readFileSync(absFile, "utf8");
    const spans = /\.[cm]?[jt]sx?$/.test(absFile) ? extractJsFunctionSpans(absFile, source) : extractFallbackFunctionSpans(absFile, source);
    const ownedCov = computeOwnedSpanCoverage(spans, detailed.lineHits.get(fileRel), detailed.branchHits?.get(fileRel));
    let fileWorstCrap = 0; let fileWorstCc = 1; let fileWorstCov = 1;
    for (let i = 0; i < spans.length; i++) {
      const span = spans[i]; if (!span) continue;
      const cov = ownedCov.get(i) ?? 0; const score = computeCrapScore(span.cc, cov);
      if (score > fileWorstCrap) { fileWorstCrap = score; fileWorstCc = span.cc; fileWorstCov = cov; }
    }
    if (fileWorstCrap > worstCrap) worstCrap = fileWorstCrap;
    if (fileWorstCrap > maxAllowed) offenders.push({ file: path.relative(absRoot, absFile).split(path.sep).join("/"), cyclomaticComplexity: fileWorstCc, coveragePct: Number((fileWorstCov * 100).toFixed(1)), crapScore: fileWorstCrap });
  }
  const uncoveredRepoFiles = discoverRepo(absRoot).files.filter((f) => f.language && !f.isTest && !f.isStub && isHostRepoFile(f.rel) && !coveredRelSet.has(f.rel)).map((f) => f.rel).sort();
  offenders.sort((a, b) => b.crapScore - a.crapScore);
  return { maxAllowed, passed: evaluatedFiles > 0 && offenders.length === 0 && uncoveredRepoFiles.length === 0, worstCrap, offenders, evaluatedFiles, uncoveredRepoFiles };
}

export const reportParsers = { parseLcov, parseCoberturaXml, parseStrykerJson, parseJunitOrTrx, EXACT_REPORT_PATHS };
