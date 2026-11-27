import { parseSync } from "oxc-parser";
import type { ScannedFile } from "../discover.ts";
import { lineOf, maskCode } from "../test-lexical.ts";
import type { Finding } from "../types.ts";

export interface AstNode {
  type: string;
  start?: number;
  end?: number;
  [key: string]: unknown;
}

export function isAstNode(value: unknown): value is AstNode {
  return typeof value === "object" && value !== null && typeof (value as { type?: unknown }).type === "string";
}

function collectAstChildren(node: AstNode): AstNode[] {
  const children: AstNode[] = [];
  for (const [key, val] of Object.entries(node)) {
    if (key === "type" || key === "start" || key === "end") continue;
    if (Array.isArray(val)) {
      for (const child of val) if (isAstNode(child)) children.push(child);
    } else if (isAstNode(val)) {
      children.push(val);
    }
  }
  return children;
}

export function walkAst(node: AstNode, visit: (current: AstNode, parent: AstNode | null) => boolean | void, parent: AstNode | null = null): void {
  const stack: Array<{ cur: AstNode; par: AstNode | null }> = [{ cur: node, par: parent }];
  let visited = 0;
  while (stack.length > 0 && visited < 200_000) {
    visited += 1;
    const item = stack.pop();
    if (!item || visit(item.cur, item.par) === false) continue;
    const children = collectAstChildren(item.cur);
    for (let i = children.length - 1; i >= 0; i--) {
      const child = children[i];
      if (child) stack.push({ cur: child, par: item.cur });
    }
  }
}

export function hasPathologicalNesting(source: string, language = "typescript"): boolean {
  if (source.length > 2_097_152) return true;
  const masked = maskCode(source, language);
  let depth = 0;
  let unaryRun = 0;
  let bsRun = 0;
  for (let i = 0; i < masked.length; i++) {
    const c = masked.charCodeAt(i);
    if (c === 40 || c === 91 || c === 123) {
      depth += 1;
      if (depth > 128) return true;
      unaryRun = 0; bsRun = 0;
    } else if (c === 41 || c === 93 || c === 125) {
      if (depth > 0) depth -= 1;
      unaryRun = 0; bsRun = 0;
    } else if (c === 33 || c === 126 || c === 43 || c === 45) {
      unaryRun += 1;
      if (unaryRun > 128) return true;
      bsRun = 0;
    } else if (c === 92) {
      bsRun += 1;
      if (bsRun > 256) return true;
    } else if (c !== 32 && c !== 9 && c !== 10 && c !== 13) {
      unaryRun = 0; bsRun = 0;
    }
  }
  return false;
}

export function parseTsAst(file: ScannedFile): AstNode | null {
  if (file.language !== "typescript" && file.language !== "javascript") return null;
  if (hasPathologicalNesting(file.content, file.language)) return null;
  const sfcExt = file.rawContent && /\blang\s*=\s*["']tsx["']/i.test(file.rawContent)
    ? "tsx"
    : file.rawContent && /\blang\s*=\s*["']jsx["']/i.test(file.rawContent)
      ? "jsx"
      : file.language === "typescript"
        ? "ts"
        : "js";
  const virtualName = /\.(?:vue|svelte|astro)$/i.test(file.rel) ? `${file.rel}.${sfcExt}` : file.rel;
  try {
    const res = parseSync(virtualName, file.content);
    if (res.errors.length === 0 && isAstNode(res.program)) return res.program;
    if (/\.(?:js|ts)$/i.test(virtualName) && /<[A-Za-z]/.test(file.content)) {
      const jsxRes = parseSync(`${virtualName}x`, file.content);
      if (jsxRes.errors.length === 0 && isAstNode(jsxRes.program)) return jsxRes.program;
    }
    if (file.language === "javascript" && res.errors.some((e) => /return/i.test(e.message))) {
      const body = file.content.startsWith("#!") ? file.content.replace(/^#![^\n]*\n?/, "") : file.content;
      const wrapped = parseSync(virtualName, `(function(){\n${body}\n})();`);
      if (wrapped.errors.length === 0 && isAstNode(wrapped.program)) return wrapped.program;
    }
    if (file.language === "javascript" && /^\s*\.(?:pragma|import)\s+/m.test(file.content)) {
      const qmlStripped = file.content.replace(/^\s*\.(?:pragma|import)\s+[^\n]*/gm, "");
      const qmlRes = parseSync(virtualName, qmlStripped);
      if (qmlRes.errors.length === 0 && isAstNode(qmlRes.program)) return qmlRes.program;
    }
    return null;
  } catch {
    return null;
  }
}

export function getMemberChain(node: AstNode | null | undefined): string {
  const parts: string[] = [];
  let cur: AstNode | null | undefined = node;
  for (let depth = 0; depth < 16 && cur; depth++) {
    if (cur.type === "Identifier" && typeof cur.name === "string") { parts.push(cur.name); break; }
    if (cur.type === "ThisExpression") { parts.push("this"); break; }
    if (cur.type === "MemberExpression" && !cur.computed) {
      const prop = isAstNode(cur.property) && typeof cur.property.name === "string" ? cur.property.name : "";
      if (prop) parts.push(prop);
      cur = isAstNode(cur.object) ? cur.object : null;
      continue;
    }
    break;
  }
  return parts.reverse().join(".");
}

interface AstFindingSpec {
  file: ScannedFile;
  offset: number;
  rule: string;
  rung: Finding["rung"];
  severity: Finding["severity"];
  message: string;
  fix: string;
}

function push(findings: Finding[], spec: AstFindingSpec): void {
  const line = lineOf(spec.file.content, spec.offset);
  findings.push({ id: `AST:${spec.rule}:${spec.file.rel}:${line}`, rule: spec.rule, category: "structure", rung: spec.rung, severity: spec.severity, file: spec.file.rel, line, message: spec.message, fix: spec.fix });
}

const TAINT_ROOTS = /^(?:req|request)\.(?:body|query|params|headers)(?:\.|$)|^process\.argv$|^window\.location(?:\.|$)/;
const SQL_VERB = /^\s*(?:SELECT|INSERT|UPDATE|DELETE|DROP|ALTER)\b/i;

const SANITIZER_CALL = /^(?:Number|parseInt|parseFloat|encodeURIComponent|encodeURI|Boolean|String\.prototype|Math\.\w+)$/;

function isSanitizedExpr(node: AstNode | null | undefined): boolean {
  if (!node || node.type !== "CallExpression" || !isAstNode(node.callee)) return false;
  return SANITIZER_CALL.test(getMemberChain(node.callee));
}

function nodeContainsTaint(node: AstNode | null | undefined, tainted: Set<string>): boolean {
  if (!node) return false;
  let hit = false;
  walkAst(node, (cur) => {
    if (hit) return false;
    if (isSanitizedExpr(cur)) return false;
    if (cur.type === "Identifier" && typeof cur.name === "string" && tainted.has(cur.name)) {
      hit = true;
      return;
    }
    const chain = getMemberChain(cur);
    if (chain && TAINT_ROOTS.test(chain)) hit = true;
  });
  return hit;
}

function nodeContainsSqlVerb(node: AstNode | null | undefined): boolean {
  if (!node) return false;
  let hit = false;
  walkAst(node, (cur) => {
    if (hit) return;
    if (cur.type === "Literal" && typeof cur.value === "string" && SQL_VERB.test(cur.value)) hit = true;
    if (cur.type === "TemplateElement" && typeof cur.value === "object" && cur.value !== null) {
      const raw = (cur.value as { raw?: unknown }).raw;
      if (typeof raw === "string" && SQL_VERB.test(raw)) hit = true;
    }
  });
  return hit;
}

function isSqlTaintedExpr(node: AstNode | null | undefined, tainted: Set<string>, sqlTainted: Set<string>): boolean {
  if (!node) return false;
  if (node.type === "Identifier" && typeof node.name === "string" && sqlTainted.has(node.name)) return true;
  if (node.type === "TemplateLiteral" && Array.isArray(node.expressions) && node.expressions.length > 0) {
    return nodeContainsSqlVerb(node) && node.expressions.some((e) => isAstNode(e) && nodeContainsTaint(e, tainted));
  }
  if (node.type === "BinaryExpression" && node.operator === "+") {
    return nodeContainsSqlVerb(node) && nodeContainsTaint(node, tainted);
  }
  return false;
}

interface TaintState {
  file: ScannedFile;
  fnAsync: boolean;
  tainted: Set<string>;
  sqlTainted: Set<string>;
  plainObjects: Set<string>;
  aliases: Map<string, string>;
  findings: Finding[];
}

function updateTaintBindings(st: TaintState, cur: AstNode): void {
  if (!cur.type) return;
  if (cur.type === "IfStatement" && isAstNode(cur.test) && isAstNode(cur.consequent)) {
    const consSlice = st.file.content.slice(cur.consequent.start ?? 0, cur.consequent.end ?? 0);
    if (/\b(?:return|throw)\b/.test(consSlice)) {
      const testSlice = st.file.content.slice(cur.test.start ?? 0, cur.test.end ?? 0);
      for (const m of testSlice.matchAll(/\.\s*(?:has|includes)\s*\(\s*([A-Za-z_$][A-Za-z0-9_$]*)\s*\)/g)) {
        if (m[1]) st.tainted.delete(m[1]);
      }
    }
    return;
  }
  if (cur.type !== "VariableDeclarator" || !isAstNode(cur.id) || !isAstNode(cur.init)) return;
  if (cur.id.type === "Identifier" && typeof cur.id.name === "string") {
    if (nodeContainsTaint(cur.init, st.tainted)) st.tainted.add(cur.id.name);
    if (isSqlTaintedExpr(cur.init, st.tainted, st.sqlTainted)) st.sqlTainted.add(cur.id.name);
    if (cur.init.type === "Identifier" && typeof cur.init.name === "string") {
      const root = st.aliases.get(cur.init.name) ?? cur.init.name;
      st.aliases.set(cur.id.name, root);
      if (st.tainted.has(root)) st.tainted.add(cur.id.name);
      if (st.sqlTainted.has(root)) st.sqlTainted.add(cur.id.name);
      if (st.plainObjects.has(root)) st.plainObjects.add(cur.id.name);
    }
    if (cur.init.type === "ObjectExpression" && Array.isArray(cur.init.properties) && cur.init.properties.length === 0) {
      st.plainObjects.add(cur.id.name);
    }
  } else if (cur.id.type === "ObjectPattern" && Array.isArray(cur.id.properties) && nodeContainsTaint(cur.init, st.tainted)) {
    for (const prop of cur.id.properties) {
      if (isAstNode(prop) && isAstNode(prop.value) && prop.value.type === "Identifier" && typeof prop.value.name === "string") st.tainted.add(prop.value.name);
    }
  } else if (cur.id.type === "ArrayPattern" && Array.isArray(cur.id.elements) && nodeContainsTaint(cur.init, st.tainted)) {
    for (const el of cur.id.elements) {
      if (isAstNode(el) && el.type === "Identifier" && typeof el.name === "string") st.tainted.add(el.name);
    }
  }
}

function checkTaintSinks(st: TaintState, cur: AstNode): void {
  if (cur.type === "AssignmentExpression" && isAstNode(cur.left) && isAstNode(cur.right)) {
    if (
      cur.left.type === "MemberExpression" && cur.left.computed === true && isAstNode(cur.left.object) &&
      cur.left.object.type === "Identifier" && typeof cur.left.object.name === "string" &&
      st.plainObjects.has(cur.left.object.name) && isAstNode(cur.left.property) && nodeContainsTaint(cur.left.property, st.tainted)
    ) {
      push(st.findings, {
        file: st.file, offset: cur.start ?? 0, rule: "ast-unsanitized-object-index", rung: "R0", severity: "error",
        message: `Tainted dynamic key written to plain object '${cur.left.object.name}[...]' risks prototype pollution (__proto__/constructor).`,
        fix: "Use a Map or Object.create(null) instead of indexing a plain {} with request-derived keys.",
      });
    }
    if (cur.left.type === "Identifier" && typeof cur.left.name === "string") {
      if (nodeContainsTaint(cur.right, st.tainted)) st.tainted.add(cur.left.name);
      if (isSqlTaintedExpr(cur.right, st.tainted, st.sqlTainted)) st.sqlTainted.add(cur.left.name);
    }
    if (getMemberChain(cur.left).endsWith(".innerHTML") && nodeContainsTaint(cur.right, st.tainted)) {
      push(st.findings, {
        file: st.file, offset: cur.start ?? 0, rule: "ast-taint-to-sink", rung: "R0", severity: "error",
        message: "Untrusted request/location data assigned directly to innerHTML (XSS sink).",
        fix: "Use textContent or a verified HTML sanitizer instead of assigning untrusted data to innerHTML.",
      });
    }
    return;
  }
  if (cur.type !== "CallExpression" || !isAstNode(cur.callee) || !Array.isArray(cur.arguments)) return;
  const chain = getMemberChain(cur.callee);
  const firstArg = isAstNode(cur.arguments[0]) ? cur.arguments[0] : null;
  if (!firstArg) return;
  if ((chain === "res.redirect" || chain === "reply.redirect" || chain === "res.sendFile" || chain === "exec" || chain === "execSync" || chain === "child_process.exec" || chain === "child_process.execSync") && nodeContainsTaint(firstArg, st.tainted)) {
    push(st.findings, {
      file: st.file, offset: cur.start ?? 0, rule: "ast-taint-to-sink", rung: "R0", severity: "error",
      message: `Untrusted input flows directly into dangerous sink '${chain}(...)' without validation or parameterization.`,
      fix: "Validate against an explicit allowlist (for redirects/paths) or use execFileSync with an argument array (no shell).",
    });
  }
  if (/\.(?:query|execute|raw|exec)$/.test(chain) && isSqlTaintedExpr(firstArg, st.tainted, st.sqlTainted)) {
    push(st.findings, {
      file: st.file, offset: cur.start ?? 0, rule: "ast-taint-to-sink", rung: "R0", severity: "error",
      message: `Tainted SQL interpolation/concatenation passed to '${chain}(...)' (SQL injection).`,
      fix: "Pass parameterized query placeholders ($1/?) and bound values instead of interpolating or concatenating untrusted input into SQL.",
    });
  }
}

function checkAsyncTryAndEffects(st: TaintState, cur: AstNode): void {
  if (!cur.type) return;
  if (cur.type === "TryStatement" && isAstNode(cur.block) && isAstNode(cur.handler) && st.fnAsync && Array.isArray(cur.block.body)) {
    for (const stmt of cur.block.body) {
      if (!isAstNode(stmt) || stmt.type !== "ReturnStatement" || !isAstNode(stmt.argument) || stmt.argument.type !== "CallExpression" || !isAstNode(stmt.argument.callee)) continue;
      const callName = getMemberChain(stmt.argument.callee);
      const isSyncBuilder = /^(?:create|build|make)(?:Error|Response|Result|Header|Payload|Dto|View|Message|Event|Option|Config)/i.test(callName);
      if (!isSyncBuilder && !callName.endsWith("Sync") && (/^(?:fetch|load|read|write|save|send|query|commit)|(?:Async|Promise|Fetch|Query)$/i.test(callName) || /\.(?:create|update|delete|find|insert|save|load|send|query|execute|fetch)$/.test(callName))) {
        push(st.findings, {
          file: st.file, offset: stmt.start ?? 0, rule: "ast-missing-await-in-try", rung: "R1", severity: "warn",
          message: `Returning unawaited async call '${callName}()' inside try/catch bypasses the catch block on rejection.`,
          fix: "Use 'return await ...' inside try/catch so rejected promises are handled by the catch clause.",
        });
      }
    }
    return;
  }
  if (cur.type === "CallExpression" && getMemberChain(isAstNode(cur.callee) ? cur.callee : null) === "useEffect" && Array.isArray(cur.arguments)) {
    const cb = isAstNode(cur.arguments[0]) ? cur.arguments[0] : null;
    const cbBody = cb && isAstNode(cb.body) && cb.body.type === "BlockStatement" ? cb.body : null;
    if (!cbBody || !Array.isArray(cbBody.body)) return;
    let hasSub = false;
    walkAst(cbBody, (inner) => {
      if (inner.type === "CallExpression" && isAstNode(inner.callee)) {
        const c = getMemberChain(inner.callee);
        if (c === "setInterval" || c.endsWith(".addEventListener") || c.endsWith(".subscribe")) hasSub = true;
      }
      if (inner.type === "NewExpression" && isAstNode(inner.callee)) {
        const c = getMemberChain(inner.callee);
        if (c === "WebSocket" || c === "EventSource") hasSub = true;
      }
    });
    const hasCleanupReturn = cbBody.body.some((s) => isAstNode(s) && s.type === "ReturnStatement" && isAstNode(s.argument));
    if (hasSub && !hasCleanupReturn) {
      push(st.findings, {
        file: st.file, offset: cur.start ?? 0, rule: "affine-uncleaned-effect-subscription", rung: "R1", severity: "warn",
        message: "useEffect registers an event listener, interval, or subscription without returning a cleanup function.",
        fix: "Return a teardown callback from useEffect to remove listeners, clear intervals, or close subscriptions on unmount.",
      });
    }
    return;
  }
  if (cur.type === "ExpressionStatement" && isAstNode(cur.expression) && cur.expression.type === "CallExpression" && isAstNode(cur.expression.callee) && st.fnAsync) {
    const chain = getMemberChain(cur.expression.callee);
    if (/\.(?:execute|query|commit|rollback|savepoint)\b/i.test(chain) && /(?:session|tx|trx|transaction|db|conn|client)\./i.test(chain)) {
      push(st.findings, {
        file: st.file, offset: cur.start ?? 0, rule: "ast-floating-async-db-or-io", rung: "R0", severity: "error",
        message: `Unawaited async DB/transaction call '${chain}(...)' inside async function silently drops failures and races subsequent queries.`,
        fix: "Await every session/transaction query or savepoint call explicitly.",
      });
    }
  }
}

function checkUnbalancedStackBlock(st: TaintState, cur: AstNode): void {
  if (cur.type !== "BlockStatement" || !Array.isArray(cur.body) || cur.body.length < 3) return;
  for (let i = 0; i < cur.body.length - 1; i++) {
    const s = cur.body[i];
    if (!isAstNode(s) || s.type !== "ExpressionStatement" || !isAstNode(s.expression) || s.expression.type !== "CallExpression" || !isAstNode(s.expression.callee)) continue;
    const m = /^([A-Za-z0-9_.]+)\.(push|add)$/.exec(getMemberChain(s.expression.callee));
    const target = m?.[1];
    if (!m || !target || !/(?:stack|seen|visiting|active|memo|frames|open)/i.test(target)) continue;
    const undoMethod = m[2] === "push" ? "pop" : "delete";
    for (let j = i + 2; j < cur.body.length; j++) {
      const later = cur.body[j];
      if (!isAstNode(later) || later.type !== "ExpressionStatement" || !isAstNode(later.expression) || later.expression.type !== "CallExpression" || !isAstNode(later.expression.callee)) continue;
      if (getMemberChain(later.expression.callee) === `${target}.${undoMethod}`) {
        push(st.findings, {
          file: st.file, offset: s.start ?? 0, rule: "ast-unbalanced-stack-mutation-no-finally", rung: "R1", severity: "warn",
          message: `Paired '${target}.${m[2]}()' and '${target}.${undoMethod}()' without try/finally leaks stack/visiting state if the middle code throws.`,
          fix: `Wrap the work between '${target}.${m[2]}()' and '${target}.${undoMethod}()' in try { ... } finally { ${target}.${undoMethod}(); }.`,
        });
        break;
      }
    }
  }
}

function analyzeFunctionTaintAndEffects(fnNode: AstNode, file: ScannedFile, findings: Finding[]): void {
  const body = isAstNode(fnNode.body) ? fnNode.body : null;
  if (!body) return;
  const st: TaintState = {
    file, fnAsync: fnNode.async === true,
    tainted: new Set(), sqlTainted: new Set(), plainObjects: new Set(), aliases: new Map(), findings,
  };
  if (Array.isArray(fnNode.params)) {
    for (const p of fnNode.params) {
      if (isAstNode(p) && p.type === "Identifier" && typeof p.name === "string" && /^(?:req|request)$/.test(p.name)) st.tainted.add(`${p.name}.body`);
    }
  }
  walkAst(body, (cur) => {
    if (cur !== body && (cur.type === "FunctionDeclaration" || cur.type === "FunctionExpression" || cur.type === "ArrowFunctionExpression")) return false;
    updateTaintBindings(st, cur);
    checkTaintSinks(st, cur);
    checkAsyncTryAndEffects(st, cur);
    checkUnbalancedStackBlock(st, cur);
  });
}

export function analyzeTsAstGuards(file: ScannedFile, program?: AstNode | null): Finding[] {
  if ((file.language !== "typescript" && file.language !== "javascript") || file.isStub) return [];
  if (program === undefined && hasPathologicalNesting(file.content, file.language)) {
    return [{ id: `AST:syntax-bomb:${file.rel}:1`, rule: "syntax-nesting-bomb", category: "cheat", rung: "R0", severity: "error", file: file.rel, line: 1, message: `File '${file.rel}' exceeds safe AST nesting/size bounds (>128 depth or >2 MiB) — refusing to skip AST security analysis.`, fix: "Refactor deeply nested expressions or oversized generated payloads so AST verification can run." }];
  }
  const ast = program ?? parseTsAst(file);
  if (!ast) {
    return [{ id: `AST:parse-error:${file.rel}:1`, rule: "ts-syntax-parse-error", category: "structure", rung: "R0", severity: "error", file: file.rel, line: 1, message: `File '${file.rel}' failed TS/JS AST parsing — refusing to silently drop AST security/invariant rules.`, fix: "Fix the syntax error so OXC AST verification can analyze this file." }];
  }
  const findings: Finding[] = [];
  let nonNullCount = 0;
  walkAst(ast, (node) => {
    if (file.language === "typescript" && node.type === "TSNonNullExpression" && ++nonNullCount <= 5) {
      push(findings, { file, offset: node.start ?? 0, rule: "no-non-null-assertion", rung: "R0", severity: "warn", message: "Postfix non-null assertion ('!') silences null/undefined checks at compile time and hides contract bugs.", fix: "Narrow explicitly with an invariant guard or handle the missing value." });
    }
    if (node.type === "CallExpression" && isAstNode(node.callee) && node.callee.type === "Identifier" && node.callee.name === "eval") {
      push(findings, { file, offset: node.start ?? 0, rule: "ast-unsafe-eval-or-function", rung: "R0", severity: "error", message: "Dynamic eval() execution enables code injection (CWE-94/95) and defeats static analysis.", fix: "Replace eval() with a static lookup table, JSON.parse, or a sandboxed expression parser." });
    }
    if (node.type === "NewExpression" && isAstNode(node.callee) && node.callee.type === "Identifier" && node.callee.name === "Function") {
      push(findings, { file, offset: node.start ?? 0, rule: "ast-unsafe-eval-or-function", rung: "R0", severity: "error", message: "Dynamic new Function() code generation enables code injection (CWE-94/95).", fix: "Replace new Function() with declarative dispatch or a safe parser." });
    }
    if (node.type === "SwitchStatement" && Array.isArray(node.cases)) {
      const seen = new Set<string>();
      for (const c of node.cases) {
        if (!isAstNode(c) || !isAstNode(c.test) || c.test.type !== "Literal") continue;
        const key = `${typeof c.test.value}:${String(c.test.value)}`;
        if (seen.has(key)) push(findings, { file, offset: c.start ?? 0, rule: "ast-duplicate-switch-case", rung: "R0", severity: "error", message: `Duplicate switch case literal (${JSON.stringify(c.test.value)}) makes the later branch dead code.`, fix: "Remove or merge the duplicate switch case." });
        seen.add(key);
      }
    }
    if (node.type === "FunctionDeclaration" || node.type === "FunctionExpression" || node.type === "ArrowFunctionExpression") {
      analyzeFunctionTaintAndEffects(node, file, findings);
    }
  });
  return findings;
}
