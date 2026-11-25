import { parseSync } from "oxc-parser";
import type { ScannedFile } from "../discover.ts";
import { lineOf } from "../test-lexical.ts";
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

export function parseTsAst(file: ScannedFile): AstNode | null {
  if (file.language !== "typescript" && file.language !== "javascript") return null;
  try {
    const res = parseSync(file.rel, file.content);
    if (res.errors.length > 0 || !isAstNode(res.program)) return null;
    return res.program;
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

function nodeContainsTaint(node: AstNode | null | undefined, tainted: Set<string>): boolean {
  if (!node) return false;
  let hit = false;
  walkAst(node, (cur) => {
    if (hit) return;
    if (cur.type === "Identifier" && typeof cur.name === "string" && tainted.has(cur.name)) {
      hit = true;
      return;
    }
    const chain = getMemberChain(cur);
    if (chain && TAINT_ROOTS.test(chain)) hit = true;
  });
  return hit;
}

function analyzeFunctionTaintAndEffects(fnNode: AstNode, file: ScannedFile, findings: Finding[]): void {
  const body = isAstNode(fnNode.body) ? fnNode.body : null;
  if (!body) return;
  const tainted = new Set<string>();
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
    if (cur.type === "VariableDeclarator" && isAstNode(cur.id) && isAstNode(cur.init)) {
      if (cur.id.type === "Identifier" && typeof cur.id.name === "string") {
        if (nodeContainsTaint(cur.init, tainted)) tainted.add(cur.id.name);
        if (cur.init.type === "Identifier" && typeof cur.init.name === "string") {
          const root = aliases.get(cur.init.name) ?? cur.init.name;
          aliases.set(cur.id.name, root);
          if (tainted.has(root)) tainted.add(cur.id.name);
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
      if (
        /\.(?:query|execute|raw|exec)$/.test(chain) &&
        firstArg &&
        firstArg.type === "TemplateLiteral" &&
        Array.isArray(firstArg.quasis) &&
        Array.isArray(firstArg.expressions) &&
        firstArg.expressions.length > 0
      ) {
        const firstQuasi = isAstNode(firstArg.quasis[0]) && isAstNode(firstArg.quasis[0].value) ? String(firstArg.quasis[0].value.raw ?? "") : "";
        if (SQL_VERB.test(firstQuasi) && firstArg.expressions.some((e) => isAstNode(e) && nodeContainsTaint(e, tainted))) {
          push(
            findings,
            file,
            cur.start ?? 0,
            "ast-taint-to-sink",
            "R0",
            "error",
            `Tainted interpolation inside SQL template literal passed to '${chain}(...)' (SQL injection).`,
            "Pass parameterized query placeholders ($1/?) and bound values instead of interpolating variables into SQL.",
          );
        }
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
            if (/^(?:fetch|load|read|write|save|send|query|commit|create|update|delete)|(?:Async|Promise|Fetch|Query)$/i.test(callName)) {
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
  const ast = program ?? parseTsAst(file);
  if (!ast) return [];
  const findings: Finding[] = [];
  let nonNullCount = 0;

  walkAst(ast, (node) => {
    if (file.language === "typescript" && node.type === "TSNonNullExpression") {
      if (++nonNullCount <= 5) {
        push(
          findings,
          file,
          node.start ?? 0,
          "no-non-null-assertion",
          "R0",
          "warn",
          "Postfix non-null assertion ('!') silences null/undefined checks at compile time and hides contract bugs.",
          "Narrow explicitly with an invariant guard or handle the missing value.",
        );
      }
    }

    if (node.type === "CallExpression" && isAstNode(node.callee) && node.callee.type === "Identifier" && node.callee.name === "eval") {
      push(
        findings,
        file,
        node.start ?? 0,
        "ast-unsafe-eval-or-function",
        "R0",
        "error",
        "Dynamic eval() execution enables code injection (CWE-94/95) and defeats static analysis.",
        "Replace eval() with a static lookup table, JSON.parse, or a sandboxed expression parser.",
      );
    }

    if (node.type === "NewExpression" && isAstNode(node.callee) && node.callee.type === "Identifier" && node.callee.name === "Function") {
      push(
        findings,
        file,
        node.start ?? 0,
        "ast-unsafe-eval-or-function",
        "R0",
        "error",
        "Dynamic new Function() code generation enables code injection (CWE-94/95).",
        "Replace new Function() with declarative dispatch or a safe parser.",
      );
    }

    if (node.type === "SwitchStatement" && Array.isArray(node.cases)) {
      const seen = new Set<string>();
      for (const c of node.cases) {
        if (!isAstNode(c) || !isAstNode(c.test) || c.test.type !== "Literal") continue;
        const key = `${typeof c.test.value}:${String(c.test.value)}`;
        if (seen.has(key)) {
          push(
            findings,
            file,
            c.start ?? 0,
            "ast-duplicate-switch-case",
            "R0",
            "error",
            `Duplicate switch case literal (${JSON.stringify(c.test.value)}) makes the later branch dead code.`,
            "Remove or merge the duplicate switch case.",
          );
        }
        seen.add(key);
      }
    }

    if (node.type === "FunctionDeclaration" || node.type === "FunctionExpression" || node.type === "ArrowFunctionExpression") {
      analyzeFunctionTaintAndEffects(node, file, findings);
    }
  });

  return findings;
}
