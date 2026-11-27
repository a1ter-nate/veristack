import { parseSync } from "oxc-parser";
import type { ScannedFile } from "@veristack/plugin";
import { maskCode } from "@veristack/plugin";
import type { Finding, Language, RungId } from "@veristack/plugin";

export type TigerLang = Language | "sql" | "shell";

export interface TigerFindingSpec {
  rule: string;
  rung: RungId;
  severity: "error" | "warn";
  file: string;
  line: number;
  message: string;
  fix: string;
}

export interface FunctionUnit {
  name: string;
  startLine: number;
  endLine: number;
  codeLines: number;
  paramCount: number;
  boolParamCount: number;
  bodyText: string;
  node?: Record<string, unknown>;
}

const GENERATED_PATH =
  /(?:^|\/)(?:generated|generated-clients?|codegen|__snapshots__)\/|\.(?:gen|generated)\.[cm]?[jt]sx?$/i;
const GENERATED_HEADER = /(?:@generated|auto-generated|do\s+not\s+edit|generated\s+by\b)/i;
const EXEMPT_DIR =
  /^(?:templates|examples|samples|demo|demos|snippets|docs_src|benchmarks?|perf-measures|fuzz|docs|website)\//i;

export function pushTigerFinding(findings: Finding[], spec: TigerFindingSpec): void {
  if (!spec.rule || spec.line < 1) throw new Error(`Invalid TigerStyle finding spec: ${spec.rule}:${spec.line}`);
  findings.push({
    id: `TS:${spec.rule}:${spec.file}:${spec.line}`,
    rule: spec.rule,
    category: "structure",
    rung: spec.rung,
    severity: spec.severity,
    file: spec.file,
    line: spec.line,
    message: spec.message,
    fix: spec.fix,
  });
}

export function resolveTigerLang(file: ScannedFile): TigerLang | null {
  if (file.isTest || file.isWorkflow || file.isStub) return null;
  if (EXEMPT_DIR.test(file.rel)) return null;
  if (GENERATED_PATH.test(file.rel) && GENERATED_HEADER.test(file.content.slice(0, 600))) return null;
  if (file.language) return file.language;
  if (/\.sql$/i.test(file.rel)) return "sql";
  if (/\.(?:sh|bash|zsh)$/i.test(file.rel)) return "shell";
  return null;
}

export function maskTigerCode(content: string, lang: TigerLang): string {
  if (lang === "sql") {
    return content
      .replace(/\/\*[\s\S]*?\*\//g, (m) => m.replace(/[^\n]/g, " "))
      .replace(/--[^\n]*/g, (m) => " ".repeat(m.length));
  }
  if (lang === "shell") return maskCode(content, "python", true);
  return maskCode(content, lang, true);
}

export function lineAtOffset(source: string, offset: number): number {
  let line = 1;
  const bound = Math.min(offset, source.length);
  for (let i = 0; i < bound; i++) {
    if (source.charCodeAt(i) === 10) line += 1;
  }
  return line;
}

export function hasSafetyDirective(lines: readonly string[], lineNo: number): boolean {
  const startIdx = Math.max(0, lineNo - 3);
  const endIdx = Math.min(lines.length, lineNo);
  for (let i = startIdx; i < endIdx; i++) {
    if (/(?:\/\/|#|\/\*|--)\s*SAFETY:/i.test(lines[i] ?? "")) return true;
  }
  return false;
}

function countNonBlankLines(snippet: string): number {
  let count = 0;
  for (const raw of snippet.split(/\r?\n/)) {
    const trimmed = raw.trim();
    if (trimmed.length > 0 && !trimmed.startsWith("//") && !trimmed.startsWith("#") && !trimmed.startsWith("--")) {
      count += 1;
    }
  }
  return count;
}

function countTsBoolParams(params: readonly unknown[], source: string): number {
  let bools = 0;
  for (const p of params) {
    if (!p || typeof p !== "object") continue;
    const rec = p as Record<string, unknown>;
    if (typeof rec.start !== "number" || typeof rec.end !== "number") continue;
    const text = source.slice(rec.start, rec.end);
    if (/:\s*boolean\b|=\s*(?:true|false)\b/.test(text)) bools += 1;
  }
  return bools;
}

function resolveTsFuncName(node: Record<string, unknown>, parent?: Record<string, unknown>): string {
  const id = node.id as Record<string, unknown> | undefined;
  if (id && typeof id.name === "string") return id.name;
  if (parent?.type === "VariableDeclarator") {
    const pid = parent.id as Record<string, unknown> | undefined;
    if (pid && typeof pid.name === "string") return pid.name;
  }
  if (parent?.type === "MethodDefinition" || parent?.type === "Property") {
    const key = parent.key as Record<string, unknown> | undefined;
    if (key && typeof key.name === "string") return key.name;
  }
  return "<anonymous>";
}

function extractTsFunctionUnits(file: ScannedFile): FunctionUnit[] {
  if (!file.content) return [];
  let parsed: ReturnType<typeof parseSync>;
  try { parsed = parseSync(file.rel, file.content); } catch { return []; }
  const maskedFile = maskTigerCode(file.content, file.language === "javascript" ? "javascript" : "typescript");
  const out: FunctionUnit[] = [];
  const stack: Array<{ node: unknown; parent?: Record<string, unknown> }> = [{ node: parsed.program }];
  const maxNodes = 60_000;
  let visited = 0;
  while (stack.length > 0 && visited < maxNodes) {
    visited += 1;
    const entry = stack.pop();
    const cur = entry?.node;
    if (!cur || typeof cur !== "object") continue;
    const rec = cur as Record<string, unknown>;
    const t = typeof rec.type === "string" ? rec.type : "";
    if (t === "FunctionDeclaration" || t === "FunctionExpression" || t === "ArrowFunctionExpression") {
      if (typeof rec.start === "number" && typeof rec.end === "number") {
        const startLine = lineAtOffset(file.content, rec.start);
        const endLine = lineAtOffset(file.content, rec.end);
        const bodyText = file.content.slice(rec.start, rec.end);
        const maskedBody = maskedFile.slice(rec.start, rec.end);
        const params = Array.isArray(rec.params) ? rec.params : [];
        out.push({
          name: resolveTsFuncName(rec, entry?.parent),
          startLine,
          endLine,
          codeLines: countNonBlankLines(maskedBody),
          paramCount: params.length,
          boolParamCount: countTsBoolParams(params, file.content),
          bodyText,
          node: rec,
        });
      }
    }
    for (const val of Object.values(rec)) {
      if (Array.isArray(val)) {
        for (const item of val) stack.push({ node: item, parent: rec });
      } else if (val && typeof val === "object") {
        stack.push({ node: val, parent: rec });
      }
    }
  }
  return out;
}

function findBraceSpanEnd(masked: string, openIdx: number): number {
  let depth = 0;
  const maxChars = 40_000;
  const limit = Math.min(masked.length, openIdx + maxChars);
  for (let i = openIdx; i < limit; i++) {
    const ch = masked[i];
    if (ch === "{") depth += 1;
    else if (ch === "}") {
      depth -= 1;
      if (depth === 0) return i;
    }
  }
  return -1;
}

function countParamsFromHeader(paramSlice: string, lang: TigerLang): { params: number; bools: number } {
  const clean = paramSlice.trim();
  if (!clean) return { params: 0, bools: 0 };
  const parts = clean.split(",").map((s) => s.trim()).filter((s) => s.length > 0 && s !== "self" && s !== "&self" && s !== "&mut self" && s !== "cls");
  const boolRe = lang === "python" ? /:\s*bool\b|=\s*(?:True|False)\b/ : /\bbool(?:ean)?\b/;
  let bools = 0;
  for (const p of parts) if (boolRe.test(p)) bools += 1;
  return { params: parts.length, bools };
}

function extractBraceLangUnits(file: ScannedFile, lang: TigerLang): FunctionUnit[] {
  if (!file.content) return [];
  const masked = maskTigerCode(file.content, lang);
  const headerRe =
    lang === "rust"
      ? /\b(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?fn\s+([A-Za-z_]\w*)(?:\s*<[^>]*>)?\s*\(([^)]*)\)/g
      : lang === "go"
        ? /\bfunc\s+(?:\([^)]*\)\s*)?([A-Za-z_]\w*)\s*\(([^)]*)\)/g
        : lang === "csharp"
          ? /\b(?:public|private|internal|protected)\s+(?:static\s+|async\s+|virtual\s+|override\s+)*[A-Za-z0-9_<>,.\s?]+\s+([A-Za-z_]\w*)\s*\(([^)]*)\)/g
          : /(?:^|\n)\s*(?:function\s+)?([A-Za-z_]\w*)\s*\(\s*\)\s*\{/g;
  const out: FunctionUnit[] = [];
  for (const m of masked.matchAll(headerRe)) {
    const idx = m.index ?? -1;
    const name = m[1] ?? "";
    if (idx < 0 || !name) continue;
    if (lang === "csharp" && /^(?:if|for|foreach|while|switch|catch|using|lock)$/.test(name)) continue;
    const braceIdx = masked.indexOf("{", idx + m[0].length - 1);
    const semiIdx = masked.indexOf(";", idx + m[0].length);
    if (braceIdx < 0 || (semiIdx >= 0 && semiIdx < braceIdx)) continue;
    const endIdx = findBraceSpanEnd(masked, braceIdx);
    if (endIdx < 0) continue;
    const bodyText = file.content.slice(idx, endIdx + 1);
    const maskedBody = masked.slice(idx, endIdx + 1);
    const counts = countParamsFromHeader(m[2] ?? "", lang);
    out.push({
      name,
      startLine: lineAtOffset(file.content, idx),
      endLine: lineAtOffset(file.content, endIdx),
      codeLines: countNonBlankLines(maskedBody),
      paramCount: counts.params,
      boolParamCount: counts.bools,
      bodyText,
    });
  }
  return out;
}

function extractPythonUnits(file: ScannedFile): FunctionUnit[] {
  if (!file.content) return [];
  const lines = file.content.split(/\r?\n/);
  const out: FunctionUnit[] = [];
  for (let i = 0; i < lines.length; i++) {
    const raw = lines[i] ?? "";
    const m = /^(\s*)(?:async\s+)?def\s+([A-Za-z_]\w*)\s*\(([^)]*)\)/.exec(raw);
    if (!m?.[2]) continue;
    const baseIndent = (m[1] ?? "").length;
    let endIdx = i;
    for (let j = i + 1; j < lines.length; j++) {
      const next = lines[j] ?? "";
      const trim = next.trim();
      if (!trim || trim.startsWith("#")) continue;
      const ind = next.length - next.trimStart().length;
      if (ind <= baseIndent) break;
      endIdx = j;
    }
    const bodyText = lines.slice(i, endIdx + 1).join("\n");
    const counts = countParamsFromHeader(m[3] ?? "", "python");
    out.push({
      name: m[2],
      startLine: i + 1,
      endLine: endIdx + 1,
      codeLines: countNonBlankLines(bodyText),
      paramCount: counts.params,
      boolParamCount: counts.bools,
      bodyText,
    });
  }
  return out;
}

const FUNCTION_UNIT_CACHE = new WeakMap<ScannedFile, FunctionUnit[]>();

export function extractFunctionUnits(file: ScannedFile): FunctionUnit[] {
  const cached = FUNCTION_UNIT_CACHE.get(file);
  if (cached) return cached;
  const lang = resolveTigerLang(file);
  let units: FunctionUnit[] = [];
  if (lang === "typescript" || lang === "javascript") units = extractTsFunctionUnits(file);
  else if (lang === "python") units = extractPythonUnits(file);
  else if (lang === "rust" || lang === "go" || lang === "csharp" || lang === "shell") {
    units = extractBraceLangUnits(file, lang);
  }
  FUNCTION_UNIT_CACHE.set(file, units);
  return units;
}
