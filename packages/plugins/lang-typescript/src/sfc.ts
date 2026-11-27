import { canStartJsRegex, type Language } from "@veristack/plugin";

function findSfcTagClose(raw: string, start: number): number {
  let attrQ = "";
  for (let k = start; k < raw.length; k++) {
    const ac = raw[k] ?? "";
    if (attrQ) { if (ac === attrQ) attrQ = ""; continue; }
    if (ac === '"' || ac === "'") { attrQ = ac; continue; }
    if (ac === ">") return k;
  }
  return -1;
}

function skipJsRegexLiteral(raw: string, start: number): number {
  let rj = start + 1;
  let inCls = false;
  while (rj < raw.length && raw[rj] !== "\n" && raw[rj] !== "\r") {
    if (raw[rj] === "\\") { rj += 2; continue; }
    if (raw[rj] === "[") inCls = true;
    else if (raw[rj] === "]") inCls = false;
    else if (raw[rj] === "/" && !inCls) return rj + 1;
    rj += 1;
  }
  return -1;
}

function findSfcScriptEnd(raw: string, bodyStart: number): { bodyEnd: number; closeLen: number } {
  if (!raw || bodyStart >= raw.length) return { bodyEnd: -1, closeLen: 0 };
  let j = bodyStart;
  let q = "";
  const tplStack: number[] = [];
  while (j < raw.length) {
    const ch = raw[j] ?? "";
    const nx = raw[j + 1] ?? "";
    if (q) {
      if (ch === "\\") { j += 2; continue; }
      if (q === "`" && ch === "$" && nx === "{") { q = ""; tplStack.push(0); j += 2; continue; }
      if (ch === q) q = "";
      j += 1;
      continue;
    }
    if (tplStack.length > 0 && (ch === "{" || ch === "}")) {
      const top = tplStack[tplStack.length - 1] ?? 0;
      if (ch === "{") tplStack[tplStack.length - 1] = top + 1;
      else if (top === 0) { tplStack.pop(); q = "`"; }
      else tplStack[tplStack.length - 1] = top - 1;
      j += 1;
      continue;
    }
    if (ch === "/" && nx === "/") { while (j < raw.length && raw[j] !== "\n") j += 1; continue; }
    if (ch === "/" && nx === "*") { const e = raw.indexOf("*/", j + 2); j = e < 0 ? raw.length : e + 2; continue; }
    if (ch === "/" && nx !== "/" && nx !== "*" && canStartJsRegex(raw, j)) {
      const afterRegex = skipJsRegexLiteral(raw, j);
      if (afterRegex >= 0) { j = afterRegex; continue; }
    }
    if (ch === "'" && j > bodyStart && /[A-Za-z]/.test(raw[j - 1] ?? "") && /[A-Za-z]/.test(nx)) { j += 1; continue; }
    if (ch === '"' || ch === "'" || ch === "`") { q = ch; j += 1; continue; }
    if (ch === "<" && nx === "/") {
      const cm = /^<\/script\s*>/i.exec(raw.slice(j, j + 16));
      if (cm) return { bodyEnd: j, closeLen: cm[0].length };
    }
    j += 1;
  }
  return { bodyEnd: -1, closeLen: 0 };
}

export function scanSfcScriptSpans(raw: string): Array<{ attrs: string; bodyStart: number; bodyEnd: number }> {
  const spans: Array<{ attrs: string; bodyStart: number; bodyEnd: number }> = [];
  if (!raw) return spans;
  for (let i = 0; i < raw.length; ) {
    if (raw.startsWith("<!--", i)) { const e = raw.indexOf("-->", i + 4); if (e < 0) break; i = e + 3; continue; }
    if (raw[i] === "<" && /^<script\b/i.test(raw.slice(i, i + 8))) {
      const gt = findSfcTagClose(raw, i + 7);
      if (gt < 0) break;
      const attrs = raw.slice(i + 7, gt);
      const bodyStart = gt + 1;
      const { bodyEnd, closeLen } = findSfcScriptEnd(raw, bodyStart);
      if (bodyEnd < 0) break;
      spans.push({ attrs, bodyStart, bodyEnd });
      i = bodyEnd + closeLen;
      continue;
    }
    i += 1;
  }
  return spans;
}

export function extractSfcScript(rel: string, raw: string): { language: Language; content: string } | undefined {
  const lower = rel.toLowerCase();
  const isAstro = lower.endsWith(".astro");
  if (!isAstro && !lower.endsWith(".vue") && !lower.endsWith(".svelte")) return undefined;
  const out = Array<string>(raw.length).fill(" ");
  for (let i = 0; i < raw.length; i++) if (raw[i] === "\n") out[i] = "\n";
  let foundAny = false;
  if (isAstro) {
    const fm = /^---\r?\n([\s\S]*?)\r?\n---/.exec(raw);
    if (fm?.[1]) {
      const start = fm[0].indexOf(fm[1]);
      for (let i = 0; i < fm[1].length; i++) out[start + i] = fm[1][i] ?? " ";
      foundAny = true;
    }
  }
  const spans = scanSfcScriptSpans(raw);
  for (const sp of spans) {
    for (let i = sp.bodyStart; i < sp.bodyEnd; i++) out[i] = raw[i] ?? " ";
    foundAny = true;
  }
  if (!foundAny) return undefined;
  const isTs = isAstro || spans.some((sp) => /\blang\s*=\s*["']tsx?["']/i.test(sp.attrs));
  return { language: isTs ? "typescript" : "javascript", content: out.join("") };
}
