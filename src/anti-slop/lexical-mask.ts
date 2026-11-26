function canStartJsRegex(text: string, idx: number): boolean {
  let p = idx - 1;
  while (p >= 0 && /\s/.test(text[p] ?? "")) p -= 1;
  if (p < 0) return true;
  const prev = text[p] ?? "";
  if ("=({[,;:!?&|+-*~%^<>".includes(prev)) return true;
  if (/[A-Za-z0-9_$]/.test(prev)) {
    let s = p;
    while (s > 0 && /[A-Za-z0-9_$]/.test(text[s - 1] ?? "")) s -= 1;
    return /^(?:return|case|throw|yield|await|typeof|void|delete|in|of|new|else|do)$/.test(text.slice(s, p + 1));
  }
  return false;
}

function maskLexical(text: string, stripComments: boolean, language?: string): string {
  const isPython = language === "python";
  const isRust = language === "rust";
  const isGo = language === "go";
  const isJsLike = language === "typescript" || language === "javascript" || language === undefined;
  const out = [...text];
  let quote = ""; let tripleQuote = ""; let tripleLen = 0; let verbatimCSharp = false; let rustRawHashes = -1; let escaped = false;
  const tplBraceStack: number[] = [];
  for (let i = 0; i < text.length; i++) {
    const ch = text[i] ?? ""; const next = text[i + 1] ?? "";
    if (tripleQuote) {
      if (ch !== "\n" && ch !== "\r") out[i] = " ";
      if (ch === tripleQuote) {
        let count = 0; while (i + count < text.length && text[i + count] === tripleQuote) count += 1;
        if (count >= tripleLen) { for (let k = 0; k < count; k++) out[i + k] = " "; i += count - 1; tripleQuote = ""; tripleLen = 0; }
      }
      continue;
    }
    if (verbatimCSharp) {
      if (ch !== "\n" && ch !== "\r") out[i] = " ";
      if (ch === '"') { if (next === '"') { out[i + 1] = " "; i += 1; } else verbatimCSharp = false; }
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
      if (tplBraceStack.length > 0) {
        const top = tplBraceStack[tplBraceStack.length - 1] ?? 0;
        if (ch === "{") tplBraceStack[tplBraceStack.length - 1] = top + 1;
        else if (ch === "}") {
          if (top === 0) { tplBraceStack.pop(); quote = "`"; out[i] = " "; continue; }
          tplBraceStack[tplBraceStack.length - 1] = top - 1;
        }
      }
      if (stripComments && ((isPython && ch === "#") || (!isPython && ch === "/" && next === "/"))) {
        while (i < text.length && text[i] !== "\n") { out[i] = " "; i += 1; }
        continue;
      }
      if (stripComments && !isPython && ch === "/" && next === "*") {
        out[i] = " "; out[i + 1] = " "; i += 2;
        while (i < text.length) {
          if (text[i] === "*" && text[i + 1] === "/") { out[i] = " "; out[i + 1] = " "; i += 1; break; }
          if (text[i] !== "\n" && text[i] !== "\r") out[i] = " ";
          i += 1;
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
        if (ok) { for (let k = i + 1; k < j; k++) out[k] = " "; i = j; continue; }
      }
      if ((ch === "@" && next === '"') || ((ch === "@" && next === "$" || ch === "$" && next === "@") && text[i + 2] === '"')) {
        const len = ch === "@" && next === '"' ? 2 : 3;
        for (let k = 0; k < len; k++) out[i + k] = " ";
        i += len - 1; verbatimCSharp = true; continue;
      }
      if (isRust && (ch === "r" || (ch === "b" && next === "r")) && (i === 0 || !/[A-Za-z0-9_]/.test(text[i - 1] ?? ""))) {
        const prefixLen = ch === "b" ? 2 : 1; let hashes = 0;
        while (text[i + prefixLen + hashes] === "#") hashes += 1;
        if (text[i + prefixLen + hashes] === '"') {
          for (let k = 0; k <= prefixLen + hashes; k++) out[i + k] = " ";
          i += prefixLen + hashes; rustRawHashes = hashes; continue;
        }
      }
      if ((ch === '"' || ch === "'") && next === ch && text[i + 2] === ch) {
        let count = 3; while (text[i + count] === ch) count += 1;
        for (let k = 0; k < count; k++) out[i + k] = " ";
        i += count - 1; tripleQuote = ch; tripleLen = count; continue;
      }
      if (ch === '"' || ch === "'" || ch === "`") {
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
  return out.join("");
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
    let pDepth = 0; let bDepth = 0; let brace = -1; let semi = -1;
    for (let i = scan; i < masked.length; i++) {
      const c = masked[i] ?? "";
      if (c === "(") pDepth += 1;
      else if (c === ")" && pDepth > 0) pDepth -= 1;
      else if (c === "[") bDepth += 1;
      else if (c === "]" && bDepth > 0) bDepth -= 1;
      else if (pDepth === 0 && bDepth === 0) {
        if (c === ";") { semi = i; break; }
        if (c === "{") { brace = i; break; }
      }
    }
    if (semi >= 0) {
      for (let i = pos; i <= semi; i++) if (out[i] !== "\n") out[i] = " ";
      idx = semi + 1; continue;
    }
    if (brace < 0) break;
    let depth = 0; let end = brace;
    for (let i = brace; i < masked.length; i++) {
      if (masked[i] === "{") depth += 1;
      else if (masked[i] === "}" && --depth === 0) { end = i; break; }
    }
    for (let i = pos; i <= end; i++) if (out[i] !== "\n") out[i] = " ";
    idx = end + 1;
  }
  return out.join("");
}

export function maskStrings(text: string): string {
  return maskLexical(text, false);
}

export function maskCode(text: string, language?: string, prodOnly = false, includeStandaloneRustTests = false): string {
  const masked = maskLexical(text, true, language);
  return prodOnly && language === "rust" ? blankRustCfgTest(masked, includeStandaloneRustTests) : masked;
}
