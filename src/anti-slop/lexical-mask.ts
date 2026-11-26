function canStartJsRegex(text: string, idx: number): boolean {
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
    return /^(?:return|case|throw|yield|await|typeof|void|delete|in|of|new|else|do)$/.test(text.slice(s, p + 1));
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

export function scanLexical(text: string, stripComments: boolean, language?: string): LexicalScanResult {
  const isPython = language === "python";
  const isRust = language === "rust";
  const isGo = language === "go";
  const isCsharp = language === "csharp";
  const isSql = language === "sql";
  const isJsLike = language === "typescript" || language === "javascript" || language === undefined;
  const out = [...text];
  const regexSpans: Array<{ start: number; end: number }> = [];
  const commentSpans: LexicalCommentSpan[] = [];
  let quote = ""; let tripleQuote = ""; let tripleLen = 0; let tripleRaw = false; let tripleEscaped = false;
  let verbatimCSharp = false; let verbatimInterpDepth = 0; let rustRawHashes = -1; let sqlDollarTag = "";
  let escaped = false; let line = 1; let seenCode = false; let atBol = true;
  const tplBraceStack: number[] = [];

  let i = 0;
  if (text.startsWith("#!")) {
    while (i < text.length && text[i] !== "\n") { if (stripComments) out[i] = " "; i += 1; }
  }

  for (; i < text.length; i++) {
    const ch = text[i] ?? ""; const next = text[i + 1] ?? "";
    if (ch === "\n") { line += 1; atBol = true; }
    if (sqlDollarTag) {
      if (ch !== "\n" && ch !== "\r") out[i] = " ";
      if (ch === "$" && text.startsWith(sqlDollarTag, i)) {
        for (let k = 0; k < sqlDollarTag.length; k++) out[i + k] = " ";
        i += sqlDollarTag.length - 1; sqlDollarTag = "";
      }
      continue;
    }
    if (tripleQuote) {
      if (ch !== "\n" && ch !== "\r") out[i] = " ";
      if (tripleEscaped) { tripleEscaped = false; continue; }
      if (!isCsharp && !tripleRaw && ch === "\\") { tripleEscaped = true; continue; }
      if (ch === tripleQuote) {
        let count = 0;
        const maxTake = isCsharp ? text.length - i : Math.min(tripleLen, text.length - i);
        while (count < maxTake && text[i + count] === tripleQuote) count += 1;
        if (count >= tripleLen) {
          for (let k = 0; k < count; k++) out[i + k] = " ";
          i += count - 1; tripleQuote = ""; tripleLen = 0; tripleRaw = false;
        }
      }
      continue;
    }
    if (verbatimCSharp) {
      if (ch !== "\n" && ch !== "\r") out[i] = " ";
      if (verbatimInterpDepth >= 0 && ch === "{") {
        if (next === "{") { out[i + 1] = " "; i += 1; continue; }
        verbatimInterpDepth += 1; continue;
      }
      if (verbatimInterpDepth > 0) {
        if (ch === "}") { verbatimInterpDepth -= 1; continue; }
        if (ch === '"') {
          let k = i + 1;
          while (k < text.length && text[k] !== "\n") {
            if (text[k] !== "\r") out[k] = " ";
            if (text[k] === "\\") { k += 2; continue; }
            if (text[k] === '"') break;
            k += 1;
          }
          i = Math.min(k, text.length - 1);
          continue;
        }
        continue;
      }
      if (ch === '"') { if (next === '"') { out[i + 1] = " "; i += 1; } else { verbatimCSharp = false; verbatimInterpDepth = -1; } }
      continue;
    }
    if (rustRawHashes >= 0) {
      if (ch !== "\n" && ch !== "\r") out[i] = " ";
      if (ch === '"') {
        let hashes = 0; while (hashes < rustRawHashes && text[i + 1 + hashes] === "#") hashes += 1;
        if (hashes === rustRawHashes) { for (let k = 1; k <= hashes; k++) out[i + k] = " "; i += hashes; rustRawHashes = -1; }
      }
      continue;
    }
    if (!quote) {
      if (ch === "\n" || /\s/.test(ch)) continue;
      if (tplBraceStack.length > 0) {
        const top = tplBraceStack[tplBraceStack.length - 1] ?? 0;
        if (ch === "{") tplBraceStack[tplBraceStack.length - 1] = top + 1;
        else if (ch === "}") {
          if (top === 0) { tplBraceStack.pop(); quote = "`"; out[i] = " "; continue; }
          tplBraceStack[tplBraceStack.length - 1] = top - 1;
        }
      }
      if (isCsharp && atBol && ch === "#") {
        seenCode = true; atBol = false;
        while (i < text.length && text[i] !== "\n") i += 1;
        if (text[i] === "\n") { line += 1; atBol = true; }
        continue;
      }
      if ((isPython && ch === "#") || (isSql && ch === "-" && next === "-") || (!isPython && !isSql && ch === "/" && next === "/")) {
        const start = i; const startLine = line; const prefixLen = isPython ? 1 : 2;
        if (stripComments) { out[i] = " "; if (prefixLen === 2) out[i + 1] = " "; }
        i += prefixLen;
        const bodyStart = i;
        while (i < text.length && text[i] !== "\n") { if (stripComments) out[i] = " "; i += 1; }
        commentSpans.push({ start, end: i, line: startLine, endLine: startLine, kind: "line", text: text.slice(bodyStart, i), header: !seenCode });
        if (text[i] === "\n") { line += 1; atBol = true; }
        continue;
      }
      if (!isPython && ch === "/" && next === "*") {
        const start = i; const startLine = line;
        if (stripComments) { out[i] = " "; out[i + 1] = " "; }
        i += 2;
        const bodyStart = i;
        while (i < text.length) {
          if (text[i] === "*" && text[i + 1] === "/") {
            commentSpans.push({ start, end: i + 2, line: startLine, endLine: line, kind: "block", text: text.slice(bodyStart, i), header: !seenCode });
            if (stripComments) { out[i] = " "; out[i + 1] = " "; }
            i += 1; break;
          }
          if (text[i] === "\n") line += 1;
          else if (stripComments && text[i] !== "\r") out[i] = " ";
          i += 1;
        }
        continue;
      }
      seenCode = true; atBol = false;
      if (isSql) {
        if (ch === "$") {
          const dm = /^\$([A-Za-z0-9_]*)\$/.exec(text.slice(i, i + 40));
          if (dm?.[0]) {
            sqlDollarTag = dm[0];
            for (let k = 0; k < sqlDollarTag.length; k++) out[i + k] = " ";
            i += sqlDollarTag.length - 1; continue;
          }
        }
        if (ch === "'") {
          out[i] = " "; i += 1;
          while (i < text.length) {
            if (text[i] === "\n") line += 1;
            else if (text[i] !== "\r") out[i] = " ";
            if (text[i] === "'") {
              if (text[i + 1] === "'") { out[i + 1] = " "; i += 2; continue; }
              break;
            }
            i += 1;
          }
        }
        continue;
      }
      if (isJsLike && ch === "/" && next !== "/" && next !== "*" && canStartJsRegex(text, i)) {
        let j = i + 1; let inClass = false; let ok = false;
        while (j < text.length && text[j] !== "\n" && text[j] !== "\r") {
          const rc = text[j] ?? "";
          if (rc === "\\") { j += 2; continue; }
          if (rc === "[") inClass = true;
          else if (rc === "]") inClass = false;
          else if (rc === "/" && !inClass) { ok = true; break; }
          j += 1;
        }
        if (ok) {
          regexSpans.push({ start: i, end: j });
          for (let k = i + 1; k < j; k++) out[k] = " ";
          i = j; continue;
        }
      }
      if (isCsharp && ch === "$") {
        let dollars = 0; while (text[i + dollars] === "$") dollars += 1;
        let qCount = 0; while (text[i + dollars + qCount] === '"') qCount += 1;
        if (qCount >= 3) {
          for (let k = 0; k < dollars + qCount; k++) out[i + k] = " ";
          i += dollars + qCount - 1; tripleQuote = '"'; tripleLen = qCount; tripleRaw = true; continue;
        }
      }
      if ((isCsharp || language === undefined) && ((ch === "@" && next === '"') || (((ch === "@" && next === "$") || (ch === "$" && next === "@")) && text[i + 2] === '"'))) {
        const isInterp = !(ch === "@" && next === '"');
        const len = isInterp ? 3 : 2;
        for (let k = 0; k < len; k++) out[i + k] = " ";
        i += len - 1; verbatimCSharp = true; verbatimInterpDepth = isInterp ? 0 : -1; continue;
      }
      if (isRust && (ch === "r" || (ch === "b" && next === "r") || (ch === "c" && next === "r")) && (i === 0 || !/[A-Za-z0-9_]/.test(text[i - 1] ?? ""))) {
        const prefixLen = ch === "r" ? 1 : 2; let hashes = 0;
        while (text[i + prefixLen + hashes] === "#") hashes += 1;
        if (text[i + prefixLen + hashes] === '"') {
          for (let k = 0; k <= prefixLen + hashes; k++) out[i + k] = " ";
          i += prefixLen + hashes; rustRawHashes = hashes; continue;
        }
      }
      if ((isPython || isCsharp || language === undefined) && (ch === '"' || ((isPython || language === undefined) && ch === "'")) && next === ch && text[i + 2] === ch) {
        let count = 3;
        if (isCsharp) while (text[i + count] === ch) count += 1;
        const prevCh = i > 0 ? (text[i - 1] ?? "") : "";
        const prev2 = i > 1 ? (text[i - 2] ?? "") : "";
        tripleRaw = isCsharp || (isPython && (prevCh === "r" || prevCh === "R" || prev2 === "r" || prev2 === "R"));
        for (let k = 0; k < count; k++) out[i + k] = " ";
        i += count - 1; tripleQuote = ch; tripleLen = count; tripleEscaped = false; continue;
      }
      if (ch === '"' || ch === "'" || (ch === "`" && !isRust && !isCsharp)) {
        if (isRust && ch === "'" && (next === "_" || /[A-Za-z]/.test(next)) && (text[i + 2] ?? "") !== "'") continue;
        quote = ch; out[i] = " ";
      }
      continue;
    }
    if (ch === "\n" || ch === "\r") { escaped = false; if (quote !== "`") quote = ""; continue; }
    if (quote === "`" && isJsLike && !escaped && ch === "$" && next === "{") {
      out[i] = " "; out[i + 1] = " "; i += 1; quote = ""; tplBraceStack.push(0); continue;
    }
    out[i] = " ";
    if (escaped) { escaped = false; continue; }
    if (ch === "\\" && !(isGo && quote === "`")) { escaped = true; continue; }
    if (ch === quote) quote = "";
  }
  return { masked: out.join(""), regexSpans, commentSpans };
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

function blankRustCfgTest(masked: string, includeStandaloneTests = false): string {
  const out = [...masked];
  let idx = 0;
  while (idx < masked.length) {
    const pos = masked.indexOf("#[", idx);
    if (pos < 0) break;
    let bracketDepth = 0; let attrEnd = -1;
    for (let i = pos + 1; i < masked.length; i++) {
      if (masked[i] === "[") bracketDepth += 1;
      else if (masked[i] === "]" && --bracketDepth === 0) { attrEnd = i; break; }
    }
    if (attrEnd < 0) break;
    const kind = classifyRustTestAttr(masked.slice(pos + 2, attrEnd), includeStandaloneTests);
    if (kind === "none") { idx = attrEnd + 1; continue; }
    if (kind === "attr-only") {
      for (let i = pos; i <= attrEnd; i++) if (out[i] !== "\n") out[i] = " ";
      idx = attrEnd + 1; continue;
    }
    let scan = attrEnd + 1;
    while (scan < masked.length) {
      while (scan < masked.length && /\s/.test(masked[scan] ?? "")) scan += 1;
      if (masked[scan] === "#" && masked[scan + 1] === "[") {
        let d = 0; let closed = -1;
        for (let i = scan + 1; i < masked.length; i++) {
          if (masked[i] === "[") d += 1;
          else if (masked[i] === "]" && --d === 0) { closed = i + 1; break; }
        }
        if (closed < 0) { scan = masked.length; break; }
        scan = closed; continue;
      }
      break;
    }
    const isFieldOrVariant = !RUST_BLOCK_ITEM_START.test(masked.slice(scan, scan + 80));
    let pDepth = 0; let bDepth = 0; let aDepth = 0; let brace = -1; let semi = -1;
    for (let i = scan; i < masked.length; i++) {
      const c = masked[i] ?? "";
      if (c === "(") pDepth += 1;
      else if (c === ")" && pDepth > 0) pDepth -= 1;
      else if (c === "[") bDepth += 1;
      else if (c === "]" && bDepth > 0) bDepth -= 1;
      else if (c === "<") aDepth += 1;
      else if (c === ">" && masked[i - 1] !== "-" && aDepth > 0) aDepth -= 1;
      else if (pDepth === 0 && bDepth === 0 && aDepth === 0) {
        if (c === ";") { semi = i; break; }
        if (isFieldOrVariant && c === ",") { semi = i; break; }
        if (isFieldOrVariant && c === "}") { semi = Math.max(pos, i - 1); break; }
        if (c === "{") { brace = i; break; }
      }
    }
    let blankStart = pos;
    let back = pos - 1;
    while (back >= 0) {
      while (back >= 0 && /\s/.test(masked[back] ?? "")) back -= 1;
      if (back >= 0 && masked[back] === "]") {
        let d = 0; let openPos = -1;
        for (let k = back; k >= 0; k--) {
          if (masked[k] === "]") d += 1;
          else if (masked[k] === "[" && --d === 0) { openPos = k; break; }
        }
        if (openPos > 0 && masked[openPos - 1] === "#") { blankStart = openPos - 1; back = blankStart - 1; continue; }
      }
      break;
    }
    if (semi >= 0) {
      for (let i = blankStart; i <= semi; i++) if (out[i] !== "\n") out[i] = " ";
      idx = semi + 1; continue;
    }
    if (brace < 0) break;
    let depth = 0; let end = brace;
    for (let i = brace; i < masked.length; i++) {
      if (masked[i] === "{") depth += 1;
      else if (masked[i] === "}" && --depth === 0) { end = i; break; }
    }
    for (let i = blankStart; i <= end; i++) if (out[i] !== "\n") out[i] = " ";
    idx = end + 1;
  }
  return out.join("");
}

export function maskStrings(text: string, language?: string): string {
  return scanLexical(text, false, language).masked;
}

export function maskCode(text: string, language?: string, prodOnly = false, includeStandaloneRustTests = false): string {
  const masked = scanLexical(text, true, language).masked;
  return prodOnly && language === "rust" ? blankRustCfgTest(masked, includeStandaloneRustTests) : masked;
}
