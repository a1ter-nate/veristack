import type { ScannedFile } from "../discover.ts";
import type { Finding } from "../types.ts";
import {
  extractFunctionUnits,
  hasSafetyDirective,
  lineAtOffset,
  maskTigerCode,
  pushTigerFinding,
  resolveTigerLang,
  type FunctionUnit,
  type TigerLang,
} from "./helpers.ts";

const FUNCTION_LINES_WARN_MAX = 70;
const FUNCTION_LINES_ERR_MAX = 150;
const NESTING_DEPTH_MAX = 4;
const VAR_USE_SPAN_LINES_MAX = 15;

interface CfCtx {
  file: ScannedFile;
  lang: TigerLang;
  lines: readonly string[];
  units: readonly FunctionUnit[];
  findings: Finding[];
}

function checkFunctionLength(ctx: CfCtx): void {
  for (const unit of ctx.units) {
    if (unit.codeLines <= FUNCTION_LINES_WARN_MAX) continue;
    if (hasSafetyDirective(ctx.lines, unit.startLine)) continue;
    const isErr = unit.codeLines > FUNCTION_LINES_ERR_MAX;
    pushTigerFinding(ctx.findings, {
      rule: "tiger-function-length",
      rung: "R0",
      severity: isErr ? "error" : "warn",
      file: ctx.file.rel,
      line: unit.startLine,
      message: `Function '${unit.name}' has ${unit.codeLines} code lines (TigerStyle cap: ${FUNCTION_LINES_WARN_MAX}).`,
      fix: "Decompose into focused <= 70-line functions with explicit inputs and outputs.",
    });
  }
}

function isIdentChar(code: number): boolean {
  return (
    (code >= 48 && code <= 57) ||
    (code >= 65 && code <= 90) ||
    (code >= 97 && code <= 122) ||
    code === 95 ||
    code === 36
  );
}

function containsIdentifier(text: string, ident: string): boolean {
  if (!ident) return false;
  let pos = text.indexOf(ident);
  while (pos >= 0) {
    const beforeOk = pos === 0 || !isIdentChar(text.charCodeAt(pos - 1));
    const afterIdx = pos + ident.length;
    const afterOk = afterIdx >= text.length || !isIdentChar(text.charCodeAt(afterIdx));
    if (beforeOk && afterOk) return true;
    pos = text.indexOf(ident, pos + 1);
  }
  return false;
}

function collectCalledNames(body: string, selfName: string, lang: TigerLang): Set<string> {
  const masked = maskTigerCode(body, lang);
  const firstBrace = masked.indexOf("{");
  const nlIdx = masked.indexOf("\n");
  const closeParen = masked.indexOf(")");
  const colonIdx = nlIdx < 0 && closeParen >= 0 ? masked.indexOf(":", closeParen + 1) : -1;
  const slice =
    firstBrace >= 0
      ? masked.slice(firstBrace + 1)
      : nlIdx >= 0
        ? masked.slice(nlIdx + 1)
        : colonIdx >= 0
          ? masked.slice(colonIdx + 1)
          : "";
  const names = new Set<string>();
  for (const m of slice.matchAll(/(?:(?<![.\w$])|this\.)([A-Za-z_]\w*)\s*\(/g)) {
    const callee = m[1] ?? "";
    if (callee && callee !== "if" && callee !== "for" && callee !== "while" && callee !== "switch" && callee !== "catch") {
      names.add(callee);
    }
  }
  if (lang === "shell" && selfName && containsIdentifier(slice, selfName)) {
    names.add(selfName);
  }
  return names;
}

function checkSqlRecursion(ctx: CfCtx): void {
  const raw = maskTigerCode(ctx.file.content, "sql");
  for (const m of raw.matchAll(/\bWITH\s+RECURSIVE\b/gi)) {
    const idx = m.index ?? 0;
    const win = raw.slice(idx, idx + 600);
    if (!/\bLIMIT\s+\d+|\bdepth\s*<|\blevel\s*</i.test(win)) {
      pushTigerFinding(ctx.findings, {
        rule: "tiger-no-recursion",
        rung: "R0",
        severity: "error",
        file: ctx.file.rel,
        line: lineAtOffset(ctx.file.content, idx),
        message: "SQL WITH RECURSIVE CTE lacks an explicit depth or LIMIT termination bound.",
        fix: "Add an explicit depth counter guard (WHERE depth < MAX_DEPTH) and LIMIT clause.",
      });
    }
  }
}

function checkRecursion(ctx: CfCtx): void {
  if (!ctx.file.content) return;
  if (ctx.lang === "sql") { checkSqlRecursion(ctx); return; }
  const byName = new Map<string, { unit: FunctionUnit; calls: Set<string> }>();
  for (const u of ctx.units) {
    if (u.name === "<anonymous>") continue;
    byName.set(u.name, { unit: u, calls: collectCalledNames(u.bodyText, u.name, ctx.lang) });
  }
  const reported = new Set<string>();
  for (const [name, entry] of byName.entries()) {
    if (hasSafetyDirective(ctx.lines, entry.unit.startLine)) continue;
    const isDirect = entry.calls.has(name);
    let mutualPeer: string | undefined;
    if (!isDirect) {
      for (const callee of entry.calls) {
        const peer = byName.get(callee);
        if (peer && peer.calls.has(name)) { mutualPeer = callee; break; }
      }
    }
    if ((!isDirect && !mutualPeer) || reported.has(name)) continue;
    reported.add(name);
    if (mutualPeer) reported.add(mutualPeer);
    pushTigerFinding(ctx.findings, {
      rule: "tiger-no-recursion",
      rung: "R0",
      severity: "warn",
      file: ctx.file.rel,
      line: entry.unit.startLine,
      message: isDirect
        ? `Function '${name}' uses direct recursion (TigerStyle forbids unbounded recursion).`
        : `Functions '${name}' and '${mutualPeer}' form mutual recursion.`,
      fix: "Replace recursion with an explicit bounded stack/queue loop (or document a hard depth cap with '// SAFETY:').",
    });
  }
}

function checkBoundedLoopsAndQueues(ctx: CfCtx): void {
  if (ctx.lang === "sql") return;
  const masked = maskTigerCode(ctx.file.content, ctx.lang);
  const unboundedQueuePatterns: ReadonlyArray<{ langs: readonly TigerLang[]; re: RegExp; msg: string; fix: string }> = [
    { langs: ["typescript", "javascript"], re: /\b(?:Queue|PubSub)\.unbounded\s*(?:<[^>]+>)?\s*\(/g, msg: "Unbounded Queue/PubSub violates TigerStyle explicit upper bounds.", fix: "Use Queue.bounded(MAX_QUEUE_SIZE), Queue.sliding(...), or Queue.dropping(...)." },
    { langs: ["rust"], re: /\b(?:mpsc::channel|unbounded_channel|crossbeam::channel::unbounded)\s*\(\s*\)/g, msg: "Unbounded Rust channel risks OOM under backpressure.", fix: "Use mpsc::sync_channel(MAX_CAP) or bounded(MAX_CAP)." },
    { langs: ["csharp"], re: /\bChannel\.CreateUnbounded\b/g, msg: "Channel.CreateUnbounded<T>() has no capacity ceiling.", fix: "Use Channel.CreateBounded<T>(new BoundedChannelOptions(maxCapacity))." },
    { langs: ["python"], re: /\b(?:asyncio\.Queue|queue\.Queue)\s*\(\s*(?:maxsize\s*=\s*0)?\s*\)/g, msg: "Python Queue created without a positive maxsize upper bound.", fix: "Pass an explicit positive maxsize=MAX_QUEUE_SIZE." },
  ];
  for (const pat of unboundedQueuePatterns) {
    if (!pat.langs.includes(ctx.lang)) continue;
    for (const m of masked.matchAll(pat.re)) {
      const ln = lineAtOffset(ctx.file.content, m.index ?? 0);
      if (hasSafetyDirective(ctx.lines, ln)) continue;
      pushTigerFinding(ctx.findings, { rule: "tiger-unbounded-queue", rung: "R0", severity: "error", file: ctx.file.rel, line: ln, message: pat.msg, fix: pat.fix });
    }
  }
  const infLoopRe =
    ctx.lang === "python"
      ? /\bwhile\s+True\s*:/g
      : ctx.lang === "rust"
        ? /\bloop\s*\{|\bwhile\s+true\s*\{/g
        : ctx.lang === "go"
          ? /\bfor\s*\{/g
          : ctx.lang === "shell"
            ? /\bwhile\s+(?:true|:)\s*(?:;|\n)/g
            : /\bwhile\s*\(\s*true\s*\)|\bfor\s*\(\s*;\s*;\s*\)/g;
  for (const m of masked.matchAll(infLoopRe)) {
    const idx = m.index ?? 0;
    const ln = lineAtOffset(ctx.file.content, idx);
    if (hasSafetyDirective(ctx.lines, ln)) continue;
    const win = masked.slice(idx, idx + 450);
    if (/\b(?:MAX_|max[A-Z]|limit|attempts|iterations|remaining|budget|deadline|ctx\.Done)\b/.test(win)) continue;
    pushTigerFinding(ctx.findings, {
      rule: "tiger-unbounded-loop",
      rung: "R0",
      severity: "error",
      file: ctx.file.rel,
      line: ln,
      message: "Unbounded infinite loop without an explicit iteration ceiling.",
      fix: "Bound every loop with an explicit MAX_* iteration counter or add '// SAFETY:' justifying the termination proof.",
    });
  }
}

function measureTsMaxNesting(node: Record<string, unknown>): number {
  const controlTypes = new Set(["IfStatement", "ForStatement", "ForInStatement", "ForOfStatement", "WhileStatement", "DoWhileStatement", "SwitchStatement", "TryStatement"]);
  let depthMax = 0;
  const stack: Array<{ cur: unknown; depth: number }> = [{ cur: node.body, depth: 0 }];
  let visited = 0;
  while (stack.length > 0 && visited < 20_000) {
    visited += 1;
    const item = stack.pop();
    if (!item?.cur || typeof item.cur !== "object") continue;
    const rec = item.cur as Record<string, unknown>;
    const t = typeof rec.type === "string" ? rec.type : "";
    if (t === "FunctionDeclaration" || t === "FunctionExpression" || t === "ArrowFunctionExpression") continue;
    const nextDepth = controlTypes.has(t) ? item.depth + 1 : item.depth;
    if (nextDepth > depthMax) depthMax = nextDepth;
    for (const [k, v] of Object.entries(rec)) {
      if (t === "IfStatement" && k === "alternate" && v && typeof v === "object" && (v as Record<string, unknown>).type === "IfStatement") {
        stack.push({ cur: v, depth: item.depth });
        continue;
      }
      if (Array.isArray(v)) for (const x of v) stack.push({ cur: x, depth: nextDepth });
      else if (v && typeof v === "object") stack.push({ cur: v, depth: nextDepth });
    }
  }
  return depthMax;
}

function checkPushIfsUpForsDown(ctx: CfCtx): void {
  if (!ctx.file.content) return;
  if (ctx.lang === "sql") {
    const masked = maskTigerCode(ctx.file.content, "sql");
    for (const m of masked.matchAll(/\bDECLARE\s+\w+\s+CURSOR\b|\bFOR\s+\w+\s+IN\s+SELECT\b/gi)) {
      const ln = lineAtOffset(ctx.file.content, m.index ?? 0);
      if (hasSafetyDirective(ctx.lines, ln)) continue;
      pushTigerFinding(ctx.findings, {
        rule: "tiger-push-ifs-up-fors-down",
        rung: "R1",
        severity: "warn",
        file: ctx.file.rel,
        line: ln,
        message: "Row-by-row SQL cursor/loop violates 'push fors down' into set-based SQL.",
        fix: "Replace row-by-row cursor iteration with a set-based SQL query or CTE.",
      });
    }
    return;
  }
  for (const unit of ctx.units) {
    if (!unit.node || hasSafetyDirective(ctx.lines, unit.startLine)) continue;
    const depth = measureTsMaxNesting(unit.node);
    if (depth > NESTING_DEPTH_MAX) {
      pushTigerFinding(ctx.findings, {
        rule: "tiger-push-ifs-up-fors-down",
        rung: "R1",
        severity: "warn",
        file: ctx.file.rel,
        line: unit.startLine,
        message: `Function '${unit.name}' reaches control-flow nesting depth ${depth} (cap: ${NESTING_DEPTH_MAX}).`,
        fix: "Push branch dispatch up with early returns and push loops down into focused helpers.",
      });
    }
  }
}

function checkDeclareNearUse(ctx: CfCtx): void {
  if (ctx.lang !== "typescript" && ctx.lang !== "javascript") return;
  const multiUninit = /^\s*(?:let|var)\s+[A-Za-z_]\w*\s*(?::[^=,;]+)?\s*,\s*[A-Za-z_]\w*\s*(?::[^=,;]+)?\s*;/;
  for (let i = 0; i < ctx.lines.length; i++) {
    const line = ctx.lines[i] ?? "";
    if (multiUninit.test(line) && !hasSafetyDirective(ctx.lines, i + 1)) {
      pushTigerFinding(ctx.findings, {
        rule: "tiger-declare-near-use",
        rung: "R0",
        severity: "warn",
        file: ctx.file.rel,
        line: i + 1,
        message: "C89-style uninitialized multi-variable hoist separates declaration from use.",
        fix: "Declare each variable at the narrowest scope immediately before its first use.",
      });
    }
  }
  for (const u of ctx.units) {
    const bodyLines = u.bodyText.split(/\r?\n/);
    for (let i = 0; i < bodyLines.length; i++) {
      const dm = /^\s*let\s+([A-Za-z_]\w*)\s*(?::[^=;]+)?;\s*$/.exec(bodyLines[i] ?? "");
      if (!dm?.[1]) continue;
      const ident = dm[1];
      let firstUse = -1;
      for (let j = i + 1; j < bodyLines.length; j++) {
        if (containsIdentifier(bodyLines[j] ?? "", ident)) { firstUse = j; break; }
      }
      if (firstUse > 0 && firstUse - i > VAR_USE_SPAN_LINES_MAX && !hasSafetyDirective(ctx.lines, u.startLine + i)) {
        pushTigerFinding(ctx.findings, {
          rule: "tiger-declare-near-use",
          rung: "R0",
          severity: "warn",
          file: ctx.file.rel,
          line: u.startLine + i,
          message: `Variable '${ident}' is declared ${firstUse - i} lines before its first use (cap: ${VAR_USE_SPAN_LINES_MAX}).`,
          fix: `Move declaration of '${ident}' adjacent to its first assignment/use.`,
        });
      }
    }
  }
}

export function analyzeTigerControlFlow(file: ScannedFile): Finding[] {
  const lang = resolveTigerLang(file);
  if (!lang) return [];
  const ctx: CfCtx = {
    file,
    lang,
    lines: file.content.split(/\r?\n/),
    units: extractFunctionUnits(file),
    findings: [],
  };
  checkFunctionLength(ctx);
  checkRecursion(ctx);
  checkBoundedLoopsAndQueues(ctx);
  checkPushIfsUpForsDown(ctx);
  checkDeclareNearUse(ctx);
  return ctx.findings;
}
