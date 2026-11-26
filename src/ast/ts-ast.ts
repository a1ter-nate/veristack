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

export function walkAst(node: AstNode, visit: (current: AstNode, parent: AstNode | null) => boolean | void, parent: AstNode | null = null): void {
  if (visit(node, parent) === false) return;
  for (const [key, val] of Object.entries(node)) {
    if (key === "type" || key === "start" || key === "end") continue;
    if (Array.isArray(val)) {
      for (const item of val) {
        if (isAstNode(item)) walkAst(item, visit, node);
      }
    } else if (isAstNode(val)) {
      walkAst(val, visit, node);
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
    return null;
  } catch {
    return null;
  }
}

export function getMemberChain(node: AstNode | null | undefined): string {
  if (!node) return "";
  if (node.type === "Identifier" && typeof node.name === "string") return node.name;
  if (node.type === "ThisExpression") return "this";
  if (node.type === "MemberExpression" && !node.computed) {
    const obj = getMemberChain(isAstNode(node.object) ? node.object : null);
    const prop = isAstNode(node.property) && typeof node.property.name === "string" ? node.property.name : "";
    return obj && prop ? `${obj}.${prop}` : prop || obj;
  }
  return "";
}

function push(
  findings: Finding[],
  file: ScannedFile,
  offset: number,
  rule: string,
  rung: Finding["rung"],
  severity: Finding["severity"],
  message: string,
  fix: string,
): void {
  const line = lineOf(file.content, offset);
  findings.push({ id: `AST:${rule}:${file.rel}:${line}`, rule, category: "structure", rung, severity, file: file.rel, line, message, fix });
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

function analyzeFunctionTaintAndEffects(fnNode: AstNode, file: ScannedFile, findings: Finding[]): void {
  const body = isAstNode(fnNode.body) ? fnNode.body : null;
  if (!body) return;
  const tainted = new Set<string>();
  const sqlTainted = new Set<string>();
  const plainObjects = new Set<string>();
  const aliases = new Map<string, string>();

  if (Array.isArray(fnNode.params)) {
    for (const p of fnNode.params) {
      if (isAstNode(p) && p.type === "Identifier" && typeof p.name === "string" && /^(?:req|request)$/.test(p.name)) {
        tainted.add(`${p.name}.body`);
      }
    }
  }

  walkAst(body, (cur, parent) => {
    if (cur !== body && (cur.type === "FunctionDeclaration" || cur.type === "FunctionExpression" || cur.type === "ArrowFunctionExpression")) {
      return false;
    }
    if (cur.type === "IfStatement" && isAstNode(cur.test) && isAstNode(cur.consequent)) {
      const testSlice = file.content.slice(cur.test.start ?? 0, cur.test.end ?? 0);
      const consSlice = file.content.slice(cur.consequent.start ?? 0, cur.consequent.end ?? 0);
      if (/\b(?:return|throw)\b/.test(consSlice)) {
        for (const m of testSlice.matchAll(/\.\s*(?:has|includes)\s*\(\s*([A-Za-z_$][A-Za-z0-9_$]*)\s*\)/g)) {
          if (m[1]) tainted.delete(m[1]);
        }
      }
    }
    if (cur.type === "VariableDeclarator" && isAstNode(cur.id) && isAstNode(cur.init)) {
      if (cur.id.type === "Identifier" && typeof cur.id.name === "string") {
        if (nodeContainsTaint(cur.init, tainted)) tainted.add(cur.id.name);
        if (isSqlTaintedExpr(cur.init, tainted, sqlTainted)) sqlTainted.add(cur.id.name);
        if (cur.init.type === "Identifier" && typeof cur.init.name === "string") {
          const root = aliases.get(cur.init.name) ?? cur.init.name;
          aliases.set(cur.id.name, root);
          if (tainted.has(root)) tainted.add(cur.id.name);
          if (sqlTainted.has(root)) sqlTainted.add(cur.id.name);
          if (plainObjects.has(root)) plainObjects.add(cur.id.name);
        }
        if (cur.init.type === "ObjectExpression" && Array.isArray(cur.init.properties) && cur.init.properties.length === 0) {
          plainObjects.add(cur.id.name);
        }
      } else if (cur.id.type === "ObjectPattern" && Array.isArray(cur.id.properties) && nodeContainsTaint(cur.init, tainted)) {
        for (const prop of cur.id.properties) {
          if (isAstNode(prop) && isAstNode(prop.value) && prop.value.type === "Identifier" && typeof prop.value.name === "string") {
            tainted.add(prop.value.name);
          }
        }
      } else if (cur.id.type === "ArrayPattern" && Array.isArray(cur.id.elements) && nodeContainsTaint(cur.init, tainted)) {
        for (const el of cur.id.elements) {
          if (isAstNode(el) && el.type === "Identifier" && typeof el.name === "string") {
            tainted.add(el.name);
          }
        }
      }
    }

    if (
      cur.type === "AssignmentExpression" &&
      isAstNode(cur.left) &&
      cur.left.type === "MemberExpression" &&
      cur.left.computed === true &&
      isAstNode(cur.left.object) &&
      cur.left.object.type === "Identifier" &&
      typeof cur.left.object.name === "string" &&
      plainObjects.has(cur.left.object.name) &&
      isAstNode(cur.left.property) &&
      nodeContainsTaint(cur.left.property, tainted)
    ) {
      push(
        findings,
        file,
        cur.start ?? 0,
        "ast-unsanitized-object-index",
        "R0",
        "error",
        `Tainted dynamic key written to plain object '${cur.left.object.name}[...]' risks prototype pollution (__proto__/constructor).`,
        "Use a Map or Object.create(null) instead of indexing a plain {} with request-derived keys.",
      );
    }

    if (cur.type === "AssignmentExpression" && isAstNode(cur.left) && isAstNode(cur.right)) {
      if (cur.left.type === "Identifier" && typeof cur.left.name === "string") {
        if (nodeContainsTaint(cur.right, tainted)) tainted.add(cur.left.name);
        if (isSqlTaintedExpr(cur.right, tainted, sqlTainted)) sqlTainted.add(cur.left.name);
      }
      const lhs = getMemberChain(cur.left);
      if (lhs.endsWith(".innerHTML") && nodeContainsTaint(cur.right, tainted)) {
        push(
          findings,
          file,
          cur.start ?? 0,
          "ast-taint-to-sink",
          "R0",
          "error",
          "Untrusted request/location data assigned directly to innerHTML (XSS sink).",
          "Use textContent or a verified HTML sanitizer instead of assigning untrusted data to innerHTML.",
        );
      }
    }

    if (cur.type === "CallExpression" && isAstNode(cur.callee) && Array.isArray(cur.arguments)) {
      const chain = getMemberChain(cur.callee);
      const firstArg = isAstNode(cur.arguments[0]) ? cur.arguments[0] : null;
      if (
        (chain === "res.redirect" || chain === "reply.redirect" || chain === "res.sendFile" || chain === "exec" || chain === "execSync" || chain === "child_process.exec" || chain === "child_process.execSync") &&
        firstArg &&
        nodeContainsTaint(firstArg, tainted)
      ) {
        push(
          findings,
          file,
          cur.start ?? 0,
          "ast-taint-to-sink",
          "R0",
          "error",
          `Untrusted input flows directly into dangerous sink '${chain}(...)' without validation or parameterization.`,
          "Validate against an explicit allowlist (for redirects/paths) or use execFileSync with an argument array (no shell).",
        );
      }
      if (/\.(?:query|execute|raw|exec)$/.test(chain) && firstArg && isSqlTaintedExpr(firstArg, tainted, sqlTainted)) {
        push(
          findings,
          file,
          cur.start ?? 0,
          "ast-taint-to-sink",
          "R0",
          "error",
          `Tainted SQL interpolation/concatenation passed to '${chain}(...)' (SQL injection).`,
          "Pass parameterized query placeholders ($1/?) and bound values instead of interpolating or concatenating untrusted input into SQL.",
        );
      }
    }

    if (cur.type === "TryStatement" && isAstNode(cur.block) && isAstNode(cur.handler)) {
      const fnAsync = fnNode.async === true;
      if (fnAsync && Array.isArray(cur.block.body)) {
        for (const stmt of cur.block.body) {
          if (
            isAstNode(stmt) &&
            stmt.type === "ReturnStatement" &&
            isAstNode(stmt.argument) &&
            stmt.argument.type === "CallExpression" &&
            isAstNode(stmt.argument.callee)
          ) {
            const callName = getMemberChain(stmt.argument.callee);
            const isSyncBuilder = /^(?:create|build|make)(?:Error|Response|Result|Header|Payload|Dto|View|Message|Event|Option|Config)/i.test(callName);
            if (!isSyncBuilder && !callName.endsWith("Sync") && (/^(?:fetch|load|read|write|save|send|query|commit)|(?:Async|Promise|Fetch|Query)$/i.test(callName) || /\.(?:create|update|delete|find|insert|save|load|send|query|execute|fetch)$/.test(callName))) {
              push(
                findings,
                file,
                stmt.start ?? 0,
                "ast-missing-await-in-try",
                "R1",
                "warn",
                `Returning unawaited async call '${callName}()' inside try/catch bypasses the catch block on rejection.`,
                "Use 'return await ...' inside try/catch so rejected promises are handled by the catch clause.",
              );
            }
          }
        }
      }
    }

    if (cur.type === "CallExpression" && getMemberChain(isAstNode(cur.callee) ? cur.callee : null) === "useEffect" && Array.isArray(cur.arguments)) {
      const cb = isAstNode(cur.arguments[0]) ? cur.arguments[0] : null;
      const cbBody = cb && isAstNode(cb.body) && cb.body.type === "BlockStatement" ? cb.body : null;
      if (cbBody && Array.isArray(cbBody.body)) {
        let hasSub = false;
        let hasCleanupReturn = false;
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
        for (const s of cbBody.body) {
          if (isAstNode(s) && s.type === "ReturnStatement" && isAstNode(s.argument)) hasCleanupReturn = true;
        }
        if (hasSub && !hasCleanupReturn) {
          push(
            findings,
            file,
            cur.start ?? 0,
            "affine-uncleaned-effect-subscription",
            "R1",
            "warn",
            "useEffect registers an event listener, interval, or subscription without returning a cleanup function.",
            "Return a teardown callback from useEffect to remove listeners, clear intervals, or close subscriptions on unmount.",
          );
        }
      }
    }

    if (
      cur.type === "ExpressionStatement" &&
      isAstNode(cur.expression) &&
      cur.expression.type === "CallExpression" &&
      isAstNode(cur.expression.callee) &&
      fnNode.async === true
    ) {
      const chain = getMemberChain(cur.expression.callee);
      if (/\.(?:execute|query|commit|rollback|savepoint)\b/i.test(chain) && /(?:session|tx|trx|transaction|db|conn|client)\./i.test(chain)) {
        push(
          findings,
          file,
          cur.start ?? 0,
          "ast-floating-async-db-or-io",
          "R0",
          "error",
          `Unawaited async DB/transaction call '${chain}(...)' inside async function silently drops failures and races subsequent queries.`,
          "Await every session/transaction query or savepoint call explicitly.",
        );
      }
    }

    if (cur.type === "BlockStatement" && Array.isArray(cur.body) && cur.body.length >= 3) {
      for (let i = 0; i < cur.body.length - 1; i++) {
        const s = cur.body[i];
        if (!isAstNode(s) || s.type !== "ExpressionStatement" || !isAstNode(s.expression) || s.expression.type !== "CallExpression" || !isAstNode(s.expression.callee)) continue;
        const pushChain = getMemberChain(s.expression.callee);
        const m = /^([A-Za-z0-9_.]+)\.(push|add)$/.exec(pushChain);
        if (!m || !/(?:stack|seen|visiting|active|memo|frames|open)/i.test(m[1] ?? "")) continue;
        const target = m[1];
        if (!target) continue;
        const undoMethod = m[2] === "push" ? "pop" : "delete";
        for (let j = i + 2; j < cur.body.length; j++) {
          const later = cur.body[j];
          if (!isAstNode(later) || later.type !== "ExpressionStatement" || !isAstNode(later.expression) || later.expression.type !== "CallExpression" || !isAstNode(later.expression.callee)) continue;
          if (getMemberChain(later.expression.callee) === `${target}.${undoMethod}`) {
            push(
              findings,
              file,
              s.start ?? 0,
              "ast-unbalanced-stack-mutation-no-finally",
              "R1",
              "warn",
              `Paired '${target}.${m[2]}()' and '${target}.${undoMethod}()' without try/finally leaks stack/visiting state if the middle code throws.`,
              `Wrap the work between '${target}.${m[2]}()' and '${target}.${undoMethod}()' in try { ... } finally { ${target}.${undoMethod}(); }.`,
            );
            break;
          }
        }
      }
    }

    void parent;
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
      push(findings, file, node.start ?? 0, "no-non-null-assertion", "R0", "warn", "Postfix non-null assertion ('!') silences null/undefined checks at compile time and hides contract bugs.", "Narrow explicitly with an invariant guard or handle the missing value.");
    }
    if (node.type === "CallExpression" && isAstNode(node.callee) && node.callee.type === "Identifier" && node.callee.name === "eval") {
      push(findings, file, node.start ?? 0, "ast-unsafe-eval-or-function", "R0", "error", "Dynamic eval() execution enables code injection (CWE-94/95) and defeats static analysis.", "Replace eval() with a static lookup table, JSON.parse, or a sandboxed expression parser.");
    }
    if (node.type === "NewExpression" && isAstNode(node.callee) && node.callee.type === "Identifier" && node.callee.name === "Function") {
      push(findings, file, node.start ?? 0, "ast-unsafe-eval-or-function", "R0", "error", "Dynamic new Function() code generation enables code injection (CWE-94/95).", "Replace new Function() with declarative dispatch or a safe parser.");
    }
    if (node.type === "SwitchStatement" && Array.isArray(node.cases)) {
      const seen = new Set<string>();
      for (const c of node.cases) {
        if (!isAstNode(c) || !isAstNode(c.test) || c.test.type !== "Literal") continue;
        const key = `${typeof c.test.value}:${String(c.test.value)}`;
        if (seen.has(key)) push(findings, file, c.start ?? 0, "ast-duplicate-switch-case", "R0", "error", `Duplicate switch case literal (${JSON.stringify(c.test.value)}) makes the later branch dead code.`, "Remove or merge the duplicate switch case.");
        seen.add(key);
      }
    }
    if (node.type === "FunctionDeclaration" || node.type === "FunctionExpression" || node.type === "ArrowFunctionExpression") {
      analyzeFunctionTaintAndEffects(node, file, findings);
    }
  });
  return findings;
}
