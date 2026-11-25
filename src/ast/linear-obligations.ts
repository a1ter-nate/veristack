import type { ScannedFile } from "../discover.ts";
import { lineOf, maskCode } from "../test-lexical.ts";
import type { Finding } from "../types.ts";
import { type AstNode, getMemberChain, isAstNode, parseTsAst, walkAst } from "./ts-ast.ts";

const LINEAR_CONSTRUCTORS = new Set([
  "fs.openSync",
  "fs.promises.open",
  "openSync",
  "createWriteStream",
  "createReadStream",
  "fs.createWriteStream",
  "fs.createReadStream",
  "pool.connect",
  "acquireLock",
  "db.connect",
]);

const RELEASE_METHODS = new Set([
  "close",
  "closeSync",
  "end",
  "destroy",
  "release",
  "dispose",
  "abort",
  "unref",
  "commit",
  "rollback",
]);

function push(
  findings: Finding[],
  file: ScannedFile,
  offset: number,
  rule: string,
  severity: Finding["severity"],
  message: string,
  fix: string,
): void {
  const line = lineOf(file.content, offset);
  findings.push({ id: `AFF:${rule}:${file.rel}:${line}`, rule, category: "structure", rung: "R1", severity, file: file.rel, line, message, fix });
}

function getCalleeName(node: AstNode): string {
  if (node.type === "AwaitExpression" && isAstNode(node.argument)) return getCalleeName(node.argument);
  if (node.type === "CallExpression" && isAstNode(node.callee)) return getMemberChain(node.callee);
  if (node.type === "NewExpression" && isAstNode(node.callee)) return `new ${getMemberChain(node.callee)}`;
  return "";
}

function isLinearAcquisition(init: AstNode | null): { kind: string; isAbortController: boolean } | null {
  if (!init) return null;
  const callee = getCalleeName(init);
  if (!callee) return null;
  if (LINEAR_CONSTRUCTORS.has(callee)) return { kind: callee, isAbortController: false };
  if (callee === "new AbortController") return { kind: callee, isAbortController: true };
  return null;
}

function checkTsFunctionObligations(fnNode: AstNode, file: ScannedFile, findings: Finding[]): void {
  const body = isAstNode(fnNode.body) && fnNode.body.type === "BlockStatement" ? fnNode.body : null;
  if (!body || !Array.isArray(body.body)) return;

  interface Obligation {
    name: string;
    kind: string;
    offset: number;
    isAbortController: boolean;
    released: boolean;
    releasedInFinally: boolean;
    transferredOut: boolean;
    closedAtStmtIndex: number;
  }

  const obligations = new Map<string, Obligation>();

  for (let idx = 0; idx < body.body.length; idx++) {
    const stmt = body.body[idx];
    if (!isAstNode(stmt)) continue;

    if (stmt.type === "VariableDeclaration" && Array.isArray(stmt.declarations)) {
      const isUsingDecl = stmt.kind === "using" || stmt.kind === "await using";
      for (const decl of stmt.declarations) {
        if (!isAstNode(decl) || !isAstNode(decl.id) || decl.id.type !== "Identifier" || typeof decl.id.name !== "string") continue;
        const acq = isLinearAcquisition(isAstNode(decl.init) ? decl.init : null);
        if (!acq || isUsingDecl) continue;
        obligations.set(decl.id.name, {
          name: decl.id.name,
          kind: acq.kind,
          offset: decl.start ?? stmt.start ?? 0,
          isAbortController: acq.isAbortController,
          released: false,
          releasedInFinally: false,
          transferredOut: false,
          closedAtStmtIndex: -1,
        });
      }
      continue;
    }

    const markUsage = (node: AstNode, insideFinally: boolean, topLevelStmtIdx: number): void => {
      walkAst(node, (cur) => {
        if (cur.type === "ReturnStatement" && isAstNode(cur.argument)) {
          walkAst(cur.argument, (r) => {
            if (r.type === "Identifier" && typeof r.name === "string") {
              const ob = obligations.get(r.name);
              if (ob) ob.transferredOut = true;
            }
          });
        }
        if (cur.type === "CallExpression" && isAstNode(cur.callee)) {
          const chain = getMemberChain(cur.callee);
          const parts = chain.split(".");
          if (parts.length === 2) {
            const [objName, method] = parts;
            const ob = objName ? obligations.get(objName) : undefined;
            if (ob && method) {
              if (RELEASE_METHODS.has(method)) {
                ob.released = true;
                if (insideFinally) ob.releasedInFinally = true;
                if (topLevelStmtIdx >= 0 && ob.closedAtStmtIndex < 0) ob.closedAtStmtIndex = topLevelStmtIdx;
              } else if (topLevelStmtIdx > ob.closedAtStmtIndex && ob.closedAtStmtIndex >= 0 && !ob.isAbortController) {
                push(
                  findings,
                  file,
                  cur.start ?? 0,
                  "affine-use-after-close",
                  "error",
                  `Linear handle '${ob.name}' used via '.${method}()' after it was already closed/released.`,
                  `Finish all operations on '${ob.name}' before closing it in a finally block.`,
                );
              }
            }
          }
          if ((chain === "fs.closeSync" || chain === "closeSync") && Array.isArray(cur.arguments)) {
            const first = isAstNode(cur.arguments[0]) ? cur.arguments[0] : null;
            if (first?.type === "Identifier" && typeof first.name === "string") {
              const ob = obligations.get(first.name);
              if (ob) {
                ob.released = true;
                if (insideFinally) ob.releasedInFinally = true;
                if (topLevelStmtIdx >= 0 && ob.closedAtStmtIndex < 0) ob.closedAtStmtIndex = topLevelStmtIdx;
              }
            }
          }
          if (Array.isArray(cur.arguments)) {
            for (const a of cur.arguments) {
              if (isAstNode(a) && a.type === "Identifier" && typeof a.name === "string") {
                const ob = obligations.get(a.name);
                if (ob && /\.(?:on|once|pipe|register|addCleanup|track)$/i.test(chain)) ob.transferredOut = true;
              }
            }
          }
        }
        if (cur.type === "MemberExpression" && !cur.computed && isAstNode(cur.object) && cur.object.type === "Identifier" && typeof cur.object.name === "string") {
          const ob = obligations.get(cur.object.name);
          const prop = isAstNode(cur.property) && typeof cur.property.name === "string" ? cur.property.name : "";
          if (ob && ob.isAbortController && prop === "signal") {
            ob.released = true;
          }
        }
      });
    };

    if (stmt.type === "TryStatement") {
      if (isAstNode(stmt.block)) markUsage(stmt.block, false, -1);
      if (isAstNode(stmt.handler)) markUsage(stmt.handler, false, -1);
      if (isAstNode(stmt.finalizer)) markUsage(stmt.finalizer, true, -1);
    } else {
      markUsage(stmt, false, idx);
    }
  }

  for (const ob of obligations.values()) {
    if (ob.transferredOut) continue;
    if (!ob.released) {
      push(
        findings,
        file,
        ob.offset,
        "affine-unreleased-resource",
        "warn",
        `Linear resource '${ob.name}' acquired via ${ob.kind}() is never closed, released, or returned (affine obligation leak).`,
        `Close/release '${ob.name}' in a finally block (or declare with 'using' / return ownership explicitly).`,
      );
    } else if (!ob.isAbortController && !ob.releasedInFinally && body.body.length >= 3) {
      const hasThrowingBetween = body.body.some((s, i) => isAstNode(s) && i < ob.closedAtStmtIndex && (s.type === "ExpressionStatement" || s.type === "VariableDeclaration") && (s.start ?? 0) > ob.offset);
      if (hasThrowingBetween && ob.closedAtStmtIndex > 0) {
        push(
          findings,
          file,
          ob.offset,
          "affine-unreleased-resource",
          "warn",
          `Linear resource '${ob.name}' (${ob.kind}) is closed sequentially without try/finally — an intermediate exception leaks the handle.`,
          `Wrap work on '${ob.name}' in try { ... } finally { ... } so release executes on every exit path.`,
        );
      }
    }
  }
}

function checkPythonLinearObligations(file: ScannedFile, findings: Finding[]): void {
  const raw = file.content;
  const masked = maskCode(raw, "python");
  const pyAcquire = /^[ \t]*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?:sqlite3\.connect|psycopg2\.connect|pool\.connect|threading\.Lock\(\)\.acquire)\s*\(/gm;
  for (const m of masked.matchAll(pyAcquire)) {
    const idx = m.index ?? 0;
    const varName = m[1] ?? "resource";
    const lineStart = raw.lastIndexOf("\n", idx) + 1;
    const lineText = raw.slice(lineStart, raw.indexOf("\n", idx) >= 0 ? raw.indexOf("\n", idx) : raw.length);
    if (/^\s*with\b/.test(lineText)) continue;
    const after = masked.slice(idx, idx + 450);
    const hasFinallyClose = after.includes("finally:") && (after.includes(`${varName}.close(`) || after.includes(`${varName}.release(`));
    if (hasFinallyClose || after.includes(`return ${varName}`)) continue;
    push(
      findings,
      file,
      idx,
      "affine-unreleased-resource",
      "warn",
      `Python resource '${varName}' acquired outside 'with' and lacks guaranteed finally: close()/release().`,
      `Use 'with ... as ${varName}:' or close '${varName}' inside a finally: block.`,
    );
  }
}

export function analyzeLinearObligations(file: ScannedFile, program?: AstNode | null): Finding[] {
  const findings: Finding[] = [];
  if (file.language === "python") {
    checkPythonLinearObligations(file, findings);
    return findings;
  }
  if (file.language !== "typescript" && file.language !== "javascript") return findings;
  const ast = program ?? parseTsAst(file);
  if (!ast) return [];
  walkAst(ast, (node) => {
    if (node.type === "FunctionDeclaration" || node.type === "FunctionExpression" || node.type === "ArrowFunctionExpression") {
      checkTsFunctionObligations(node, file, findings);
    }
  });
  return findings;
}
