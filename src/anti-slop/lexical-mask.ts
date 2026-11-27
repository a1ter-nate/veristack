export function canStartJsRegex(text: string, idx: number): boolean {
  if (idx > 0 && text[idx - 1] === "<") return false;
  let p = idx - 1;
  while (p >= 0 && /\s/.test(text[p] ?? "")) p -= 1;
  if (p < 0) return true;
  const prev = text[p] ?? "";
  if ((prev === "+" || prev === "-") && p > 0 && text[p - 1] === prev) return false;
  if (prev === ">") return p > 0 && (text[p - 1] === "=" || text[p - 1] === ">");
  if ("=({[,;:!?&|+-*~%^<".includes(prev)) return true;
  if (prev === ")") {
    let depth = 1;
    let q = p - 1;
    while (q >= 0 && depth > 0) {
      if (text[q] === ")") depth += 1;
      else if (text[q] === "(") depth -= 1;
      q -= 1;
    }
    while (q >= 0 && /\s/.test(text[q] ?? "")) q -= 1;
    if (q >= 0 && /[A-Za-z0-9_$]/.test(text[q] ?? "")) {
      let s = q;
      while (s > 0 && /[A-Za-z0-9_$]/.test(text[s - 1] ?? "")) s -= 1;
      return /^(?:if|while|for|with)$/.test(text.slice(s, q + 1));
    }
    return false;
  }
  if (/[A-Za-z0-9_$]/.test(prev)) {
    let s = p;
    while (s > 0 && /[A-Za-z0-9_$]/.test(text[s - 1] ?? "")) s -= 1;
    let b = s - 1;
    while (b >= 0 && /\s/.test(text[b] ?? "")) b -= 1;
    if (b >= 0 && text[b] === ".") return false;
    return /^(?:return|case|default|throw|yield|await|typeof|void|delete|in|of|new|else|do)$/.test(text.slice(s, p + 1));
  }
  return false;
}

export interface LexicalCommentSpan {
  start: number;
  end: number;
  line: number;
  endLine: number;
  kind: "line" | "block";
  text: string;
  header: boolean;
}

export interface LexicalScanResult {
  masked: string;
  regexSpans: Array<{ start: number; end: number }>;
  commentSpans: LexicalCommentSpan[];
}

interface LexState {
  text: string;
  out: string[];
  stripComments: boolean;
  language?: string;
  isPython: boolean;
  isRust: boolean;
  isGo: boolean;
  isCsharp: boolean;
  isSql: boolean;
  isJsLike: boolean;
  regexSpans: Array<{ start: number; end: number }>;
  commentSpans: LexicalCommentSpan[];
  quote: string;
  quoteInterpDepth: number;
  tripleQuote: string;
  tripleLen: number;
  tripleRaw: boolean;
  tripleEscaped: boolean;
  verbatimCSharp: boolean;
  verbatimInterpDepth: number;
  rustRawHashes: number;
  sqlDollarTag: string;
  escaped: boolean;
  line: number;
  seenCode: boolean;
  atBol: boolean;
  tplBraceStack: number[];
  i: number;
}

function stepMultilineString(s: LexState, ch: string, next: string): boolean {
  if (!s.text) return false;
  if (s.sqlDollarTag) {
    if (ch !== "\n" && ch !== "\r") s.out[s.i] = " ";
    if (ch === "$" && s.text.startsWith(s.sqlDollarTag, s.i)) {
      for (let k = 0; k < s.sqlDollarTag.length; k++) s.out[s.i + k] = " ";
      s.i += s.sqlDollarTag.length - 1; s.sqlDollarTag = "";
    }
    return true;
  }
  if (s.tripleQuote) {
    if (ch !== "\n" && ch !== "\r") s.out[s.i] = " ";
    if (s.tripleEscaped) { s.tripleEscaped = false; return true; }
    if (!s.isCsharp && !s.tripleRaw && ch === "\\") { s.tripleEscaped = true; return true; }
    if (ch === s.tripleQuote) {
      let count = 0;
      const maxTake = s.isCsharp ? s.text.length - s.i : Math.min(s.tripleLen, s.text.length - s.i);
      while (count < maxTake && s.text[s.i + count] === s.tripleQuote) count += 1;
      if (count >= s.tripleLen) {
        for (let k = 0; k < count; k++) s.out[s.i + k] = " ";
        s.i += count - 1; s.tripleQuote = ""; s.tripleLen = 0; s.tripleRaw = false;
      }
    }
    return true;
  }
  if (s.verbatimCSharp) {
    stepVerbatimCsharp(s, ch, next);
    return true;
  }
  if (s.rustRawHashes >= 0) {
    if (ch !== "\n" && ch !== "\r") s.out[s.i] = " ";
    if (ch === '"') {
      let hashes = 0;
      while (hashes < s.rustRawHashes && s.text[s.i + 1 + hashes] === "#") hashes += 1;
      if (hashes === s.rustRawHashes) {
        for (let k = 1; k <= hashes; k++) s.out[s.i + k] = " ";
        s.i += hashes; s.rustRawHashes = -1;
      }
    }
    return true;
  }
  return false;
}

function stepVerbatimCsharp(s: LexState, ch: string, next: string): void {
  if (ch !== "\n" && ch !== "\r") s.out[s.i] = " ";
  if (s.verbatimInterpDepth >= 0 && ch === "{") {
    if (next === "{") { s.out[s.i + 1] = " "; s.i += 1; return; }
    s.verbatimInterpDepth += 1; return;
  }
  if (s.verbatimInterpDepth > 0) {
    if (ch === "}") { s.verbatimInterpDepth -= 1; return; }
    if (ch === '"') {
      let k = s.i + 1;
      while (k < s.text.length && s.text[k] !== "\n") {
        if (s.text[k] !== "\r") s.out[k] = " ";
        if (s.text[k] === "\\") { k += 2; continue; }
        if (s.text[k] === '"') break;
        k += 1;
      }
      s.i = Math.min(k, s.text.length - 1);
    }
    return;
  }
  if (ch === '"') {
    if (next === '"') { s.out[s.i + 1] = " "; s.i += 1; }
    else { s.verbatimCSharp = false; s.verbatimInterpDepth = -1; }
  }
}

function stepSqlToken(s: LexState, ch: string): void {
  if (ch === "$") {
    const dm = /^\$([A-Za-z0-9_]*)\$/.exec(s.text.slice(s.i, s.i + 40));
    if (dm?.[0]) {
      s.sqlDollarTag = dm[0];
      for (let k = 0; k < s.sqlDollarTag.length; k++) s.out[s.i + k] = " ";
      s.i += s.sqlDollarTag.length - 1;
    }
    return;
  }
  if (ch !== "'") return;
  const isPgEscape = s.i > 0 && (s.text[s.i - 1] === "E" || s.text[s.i - 1] === "e") && (s.i === 1 || !/[A-Za-z0-9_]/.test(s.text[s.i - 2] ?? ""));
  s.out[s.i] = " "; s.i += 1;
  while (s.i < s.text.length) {
    if (s.text[s.i] === "\n") s.line += 1;
    else if (s.text[s.i] !== "\r") s.out[s.i] = " ";
    if (isPgEscape && s.text[s.i] === "\\" && s.i + 1 < s.text.length) {
      if (s.text[s.i + 1] !== "\n" && s.text[s.i + 1] !== "\r") s.out[s.i + 1] = " ";
      s.i += 2; continue;
    }
    if (s.text[s.i] === "'") {
      if (s.text[s.i + 1] === "'") { s.out[s.i + 1] = " "; s.i += 2; continue; }
      break;
    }
    s.i += 1;
  }
}

function stepCommentStart(s: LexState, ch: string, next: string): boolean {
  if (!s.text) return false;
  if ((s.isPython && ch === "#") || (s.isSql && ch === "-" && next === "-") || (!s.isPython && !s.isSql && ch === "/" && next === "/")) {
    const start = s.i; const startLine = s.line; const prefixLen = s.isPython ? 1 : 2;
    if (s.stripComments) { s.out[s.i] = " "; if (prefixLen === 2) s.out[s.i + 1] = " "; }
    s.i += prefixLen;
    const bodyStart = s.i;
    while (s.i < s.text.length && s.text[s.i] !== "\n") { if (s.stripComments) s.out[s.i] = " "; s.i += 1; }
    s.commentSpans.push({ start, end: s.i, line: startLine, endLine: startLine, kind: "line", text: s.text.slice(bodyStart, s.i), header: !s.seenCode });
    if (s.text[s.i] === "\n") { s.line += 1; s.atBol = true; }
    return true;
  }
  if (!s.isPython && ch === "/" && next === "*") {
    const start = s.i; const startLine = s.line;
    if (s.stripComments) { s.out[s.i] = " "; s.out[s.i + 1] = " "; }
    s.i += 2;
    const bodyStart = s.i;
    while (s.i < s.text.length) {
      if (s.text[s.i] === "*" && s.text[s.i + 1] === "/") {
        s.commentSpans.push({ start, end: s.i + 2, line: startLine, endLine: s.line, kind: "block", text: s.text.slice(bodyStart, s.i), header: !s.seenCode });
        if (s.stripComments) { s.out[s.i] = " "; s.out[s.i + 1] = " "; }
        s.i += 1; break;
      }
      if (s.text[s.i] === "\n") s.line += 1;
      else if (s.stripComments && s.text[s.i] !== "\r") s.out[s.i] = " ";
      s.i += 1;
    }
    return true;
  }
  return false;
}

function stepRawAndTripleOpen(s: LexState, ch: string, next: string): boolean {
  if (!s.text) return false;
  if (s.isJsLike && ch === "/" && next !== "/" && next !== "*" && canStartJsRegex(s.text, s.i)) {
    let j = s.i + 1; let inClass = false; let ok = false;
    while (j < s.text.length && s.text[j] !== "\n" && s.text[j] !== "\r") {
      const rc = s.text[j] ?? "";
      if (rc === "\\") { j += 2; continue; }
      if (rc === "[") inClass = true;
      else if (rc === "]") inClass = false;
      else if (rc === "/" && !inClass) { ok = true; break; }
      j += 1;
    }
    if (ok) {
      s.regexSpans.push({ start: s.i, end: j });
      for (let k = s.i + 1; k < j; k++) s.out[k] = " ";
      s.i = j; return true;
    }
  }
  if (s.isCsharp && ch === "$") {
    let dollars = 0; while (s.text[s.i + dollars] === "$") dollars += 1;
    let qCount = 0; while (s.text[s.i + dollars + qCount] === '"') qCount += 1;
    if (qCount >= 3) {
      for (let k = 0; k < dollars + qCount; k++) s.out[s.i + k] = " ";
      s.i += dollars + qCount - 1; s.tripleQuote = '"'; s.tripleLen = qCount; s.tripleRaw = true; return true;
    }
  }
  if ((s.isCsharp || s.language === undefined) && ((ch === "@" && next === '"') || (((ch === "@" && next === "$") || (ch === "$" && next === "@")) && s.text[s.i + 2] === '"'))) {
    const isInterp = !(ch === "@" && next === '"');
    const len = isInterp ? 3 : 2;
    for (let k = 0; k < len; k++) s.out[s.i + k] = " ";
    s.i += len - 1; s.verbatimCSharp = true; s.verbatimInterpDepth = isInterp ? 0 : -1; return true;
  }
  if (s.isRust && (ch === "r" || (ch === "b" && next === "r") || (ch === "c" && next === "r")) && (s.i === 0 || !/[A-Za-z0-9_]/.test(s.text[s.i - 1] ?? ""))) {
    const prefixLen = ch === "r" ? 1 : 2; let hashes = 0;
    while (s.text[s.i + prefixLen + hashes] === "#") hashes += 1;
    if (s.text[s.i + prefixLen + hashes] === '"') {
      for (let k = 0; k <= prefixLen + hashes; k++) s.out[s.i + k] = " ";
      s.i += prefixLen + hashes; s.rustRawHashes = hashes; return true;
    }
  }
  if ((s.isPython || s.isCsharp || s.language === undefined) && (ch === '"' || ((s.isPython || s.language === undefined) && ch === "'")) && next === ch && s.text[s.i + 2] === ch) {
    let count = 3;
    if (s.isCsharp) while (s.text[s.i + count] === ch) count += 1;
    const prevCh = s.i > 0 ? (s.text[s.i - 1] ?? "") : "";
    const prev2 = s.i > 1 ? (s.text[s.i - 2] ?? "") : "";
    s.tripleRaw = s.isCsharp || (s.isPython && (prevCh === "r" || prevCh === "R" || prev2 === "r" || prev2 === "R"));
    for (let k = 0; k < count; k++) s.out[s.i + k] = " ";
    s.i += count - 1; s.tripleQuote = ch; s.tripleLen = count; s.tripleEscaped = false; return true;
  }
  return false;
}

function stepUnquoted(s: LexState, ch: string, next: string): void {
  if (ch === "\n" || /\s/.test(ch)) return;
  if (s.tplBraceStack.length > 0) {
    const top = s.tplBraceStack[s.tplBraceStack.length - 1] ?? 0;
    if (ch === "{") s.tplBraceStack[s.tplBraceStack.length - 1] = top + 1;
    else if (ch === "}") {
      if (top === 0) { s.tplBraceStack.pop(); s.quote = "`"; s.out[s.i] = " "; return; }
      s.tplBraceStack[s.tplBraceStack.length - 1] = top - 1;
    }
  }
  if (s.isCsharp && s.atBol && ch === "#") {
    s.seenCode = true; s.atBol = false;
    while (s.i < s.text.length && s.text[s.i] !== "\n") s.i += 1;
    if (s.text[s.i] === "\n") { s.line += 1; s.atBol = true; }
    return;
  }
  if (stepCommentStart(s, ch, next)) return;
  s.seenCode = true; s.atBol = false;
  if (s.isSql) { stepSqlToken(s, ch); return; }
  if (stepRawAndTripleOpen(s, ch, next)) return;
  if (ch === '"' || ch === "'" || (ch === "`" && !s.isRust && !s.isCsharp)) {
    if (s.isRust && ch === "'" && (next === "_" || /[A-Za-z]/.test(next)) && (s.text[s.i + 2] ?? "") !== "'") return;
    if (s.isJsLike && ch === "'" && s.i > 0 && /[A-Za-z]/.test(s.text[s.i - 1] ?? "") && /[A-Za-z]/.test(next)) return;
    const isCsharpInterp = s.isCsharp && ch === '"' && s.i > 0 && s.text[s.i - 1] === "$";
    const isPyFString = s.isPython && (ch === '"' || ch === "'") && s.i > 0 && (s.text[s.i - 1] === "f" || s.text[s.i - 1] === "F" || (s.i > 1 && (s.text[s.i - 2] === "f" || s.text[s.i - 2] === "F") && /[rRbB]/.test(s.text[s.i - 1] ?? "")));
    s.quote = ch; s.quoteInterpDepth = isCsharpInterp || isPyFString ? 0 : -1; s.out[s.i] = " ";
  }
}

function skipNestedInterpQuote(s: LexState, quoteCh: string): void {
  let k = s.i + 1;
  while (k < s.text.length && s.text[k] !== "\n") {
    if (s.text[k] !== "\r") s.out[k] = " ";
    if (s.text[k] === "\\") { k += 2; continue; }
    if (s.text[k] === quoteCh) break;
    k += 1;
  }
  s.i = Math.min(k, s.text.length - 1);
}

function stepQuoted(s: LexState, ch: string, next: string): void {
  if (!s.text) return;
  if (ch === "\n" || ch === "\r") { s.escaped = false; if (s.quote !== "`") { s.quote = ""; s.quoteInterpDepth = -1; } return; }
  if (s.quoteInterpDepth >= 0 && !s.escaped) {
    if (ch === "{") {
      if (next === "{") { s.out[s.i] = " "; s.out[s.i + 1] = " "; s.i += 1; return; }
      s.out[s.i] = " "; s.quoteInterpDepth += 1; return;
    }
    if (s.quoteInterpDepth > 0) {
      s.out[s.i] = " ";
      if (ch === "}") { s.quoteInterpDepth -= 1; return; }
      if (ch === '"' || ch === "'") skipNestedInterpQuote(s, ch);
      return;
    }
  }
  if (s.quote === "`" && s.isJsLike && !s.escaped && ch === "$" && next === "{") {
    s.out[s.i] = " "; s.out[s.i + 1] = " "; s.i += 1; s.quote = ""; s.quoteInterpDepth = -1; s.tplBraceStack.push(0); return;
  }
  s.out[s.i] = " ";
  if (s.escaped) { s.escaped = false; return; }
  if (ch === "\\" && !(s.isGo && s.quote === "`")) { s.escaped = true; return; }
  if (ch === s.quote) { s.quote = ""; s.quoteInterpDepth = -1; }
}

export function scanLexical(text: string, stripComments: boolean, language?: string): LexicalScanResult {
  if (!text) return { masked: "", regexSpans: [], commentSpans: [] };
  const s: LexState = {
    text, out: [...text], stripComments, language,
    isPython: language === "python", isRust: language === "rust", isGo: language === "go",
    isCsharp: language === "csharp", isSql: language === "sql",
    isJsLike: language === "typescript" || language === "javascript" || language === undefined,
    regexSpans: [], commentSpans: [],
    quote: "", quoteInterpDepth: -1, tripleQuote: "", tripleLen: 0, tripleRaw: false, tripleEscaped: false,
    verbatimCSharp: false, verbatimInterpDepth: 0, rustRawHashes: -1, sqlDollarTag: "",
    escaped: false, line: 1, seenCode: false, atBol: true, tplBraceStack: [], i: 0,
  };
  if (text.startsWith("#!")) {
    while (s.i < text.length && text[s.i] !== "\n") { if (stripComments) s.out[s.i] = " "; s.i += 1; }
  }
  for (; s.i < text.length; s.i++) {
    const ch = text[s.i] ?? ""; const next = text[s.i + 1] ?? "";
    if (ch === "\n") { s.line += 1; s.atBol = true; }
    if (stepMultilineString(s, ch, next)) continue;
    if (!s.quote) stepUnquoted(s, ch, next);
    else stepQuoted(s, ch, next);
  }
  return { masked: s.out.join(""), regexSpans: s.regexSpans, commentSpans: s.commentSpans };
}

function splitTopLevelCommas(expr: string): string[] {
  const parts: string[] = []; let depth = 0; let start = 0;
  for (let i = 0; i < expr.length; i++) {
    if (expr[i] === "(") depth += 1;
    else if (expr[i] === ")" && depth > 0) depth -= 1;
    else if (expr[i] === "," && depth === 0) { parts.push(expr.slice(start, i).trim()); start = i + 1; }
  }
  parts.push(expr.slice(start).trim());
  return parts.filter(Boolean);
}

function cfgRequiresTest(expr: string): boolean {
  const t = expr.trim();
  if (t === "test") return true;
  if (t.startsWith("not(") && t.endsWith(")")) return false;
  if (t.startsWith("all(") && t.endsWith(")")) return splitTopLevelCommas(t.slice(4, -1)).some(cfgRequiresTest);
  if (t.startsWith("any(") && t.endsWith(")")) {
    const items = splitTopLevelCommas(t.slice(4, -1));
    return items.length > 0 && items.every(cfgRequiresTest);
  }
  return false;
}

function classifyRustTestAttr(attrBody: string, includeStandaloneTests: boolean): "item" | "attr-only" | "none" {
  const cfgAttr = /^\s*cfg_attr\s*\(([\s\S]*)\)\s*$/.exec(attrBody);
  if (cfgAttr?.[1]) {
    const cond = splitTopLevelCommas(cfgAttr[1])[0] ?? "";
    return cfgRequiresTest(cond) ? "attr-only" : "none";
  }
  const cfg = /^\s*cfg\s*\(([\s\S]*)\)\s*$/.exec(attrBody);
  if (cfg?.[1]) return cfgRequiresTest(cfg[1]) ? "item" : "none";
  if (includeStandaloneTests && /^\s*(?:[A-Za-z_]\w*::)*test\b/.test(attrBody)) return "item";
  return "none";
}

const RUST_BLOCK_ITEM_START = /^(?:(?:pub(?:\s*\([^)]*\))?\s+)?(?:unsafe\s+)?(?:async\s+)?(?:const\s+)?(?:extern(?:\s+"[^"]*")?\s+)?)?(?:fn|mod|impl|trait|struct|enum|union|use|type|const|static|macro_rules!)\b/;

function findCloseBracket(masked: string, openIdx: number): number {
  let d = 0;
  for (let i = openIdx; i < masked.length; i++) {
    if (masked[i] === "[") d += 1;
    else if (masked[i] === "]" && --d === 0) return i;
  }
  return -1;
}

function rewindLeadingRustAttrs(masked: string, pos: number): number {
  let blankStart = pos;
  let back = pos - 1;
  while (back >= 0) {
    while (back >= 0 && /\s/.test(masked[back] ?? "")) back -= 1;
    if (back < 0 || masked[back] !== "]") break;
    let d = 0; let openPos = -1;
    for (let k = back; k >= 0; k--) {
      if (masked[k] === "]") d += 1;
      else if (masked[k] === "[" && --d === 0) { openPos = k; break; }
    }
    if (openPos <= 0 || masked[openPos - 1] !== "#") break;
    blankStart = openPos - 1;
    back = blankStart - 1;
  }
  return blankStart;
}

function findRustItemBoundary(masked: string, scan: number, pos: number): { semi: number; brace: number } {
  const isFieldOrVariant = !RUST_BLOCK_ITEM_START.test(masked.slice(scan, scan + 80));
  let pDepth = 0; let bDepth = 0; let aDepth = 0;
  for (let i = scan; i < masked.length; i++) {
    const c = masked[i] ?? "";
    if (c === "(") pDepth += 1;
    else if (c === ")" && pDepth > 0) pDepth -= 1;
    else if (c === "[") bDepth += 1;
    else if (c === "]" && bDepth > 0) bDepth -= 1;
    else if (c === "<") aDepth += 1;
    else if (c === ">" && masked[i - 1] !== "-" && aDepth > 0) aDepth -= 1;
    else if (pDepth === 0 && bDepth === 0 && aDepth === 0) {
      if (c === ";") return { semi: i, brace: -1 };
      if (isFieldOrVariant && c === ",") return { semi: i, brace: -1 };
      if (isFieldOrVariant && c === "}") return { semi: Math.max(pos, i - 1), brace: -1 };
      if (c === "{") return { semi: -1, brace: i };
    }
  }
  return { semi: -1, brace: -1 };
}

function blankSpan(out: string[], from: number, to: number): void {
  for (let i = from; i <= to; i++) if (out[i] !== "\n") out[i] = " ";
}

function blankRustCfgTest(masked: string, includeStandaloneTests = false): string {
  if (!masked) return "";
  const out = [...masked];
  let idx = 0;
  while (idx < masked.length) {
    const pos = masked.indexOf("#[", idx);
    if (pos < 0) break;
    const attrEnd = findCloseBracket(masked, pos + 1);
    if (attrEnd < 0) break;
    const kind = classifyRustTestAttr(masked.slice(pos + 2, attrEnd), includeStandaloneTests);
    if (kind === "none") { idx = attrEnd + 1; continue; }
    if (kind === "attr-only") { blankSpan(out, pos, attrEnd); idx = attrEnd + 1; continue; }
    let scan = attrEnd + 1;
    while (scan < masked.length) {
      while (scan < masked.length && /\s/.test(masked[scan] ?? "")) scan += 1;
      if (masked[scan] !== "#" || masked[scan + 1] !== "[") break;
      const closed = findCloseBracket(masked, scan + 1);
      if (closed < 0) { scan = masked.length; break; }
      scan = closed + 1;
    }
    const { semi, brace } = findRustItemBoundary(masked, scan, pos);
    const blankStart = rewindLeadingRustAttrs(masked, pos);
    if (semi >= 0) { blankSpan(out, blankStart, semi); idx = semi + 1; continue; }
    if (brace < 0) break;
    let depth = 0; let end = brace;
    for (let i = brace; i < masked.length; i++) {
      if (masked[i] === "{") depth += 1;
      else if (masked[i] === "}" && --depth === 0) { end = i; break; }
    }
    blankSpan(out, blankStart, end);
    idx = end + 1;
  }
  return out.join("");
}

export function maskStrings(text: string, language?: string): string {
  return scanLexical(text, false, language).masked;
}

export type MaskCodeMode = boolean | "prod" | "prod-strip-standalone-tests";

export function maskCode(text: string, language?: string, mode: MaskCodeMode = false): string {
  const masked = scanLexical(text, true, language).masked;
  const prodOnly = mode === true || mode === "prod" || mode === "prod-strip-standalone-tests";
  const includeStandaloneRustTests = mode === "prod-strip-standalone-tests";
  return prodOnly && language === "rust" ? blankRustCfgTest(masked, includeStandaloneRustTests) : masked;
}
