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

interface AffFindingSpec {
  file: ScannedFile;
  offset: number;
  rule: string;
  severity: Finding["severity"];
  message: string;
  fix: string;
}

function push(findings: Finding[], spec: AffFindingSpec): void {
  const line = lineOf(spec.file.content, spec.offset);
  findings.push({ id: `AFF:${spec.rule}:${spec.file.rel}:${line}`, rule: spec.rule, category: "structure", rung: "R1", severity: spec.severity, file: spec.file.rel, line, message: spec.message, fix: spec.fix });
}

function getCalleeName(node: AstNode): string {
  let cur: AstNode = node;
  for (let depth = 0; depth < 8 && cur.type === "AwaitExpression" && isAstNode(cur.argument); depth++) {
    cur = cur.argument;
  }
  if (cur.type === "CallExpression" && isAstNode(cur.callee)) return getMemberChain(cur.callee);
  if (cur.type === "NewExpression" && isAstNode(cur.callee)) return `new ${getMemberChain(cur.callee)}`;
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

interface ObligationCtx {
  file: ScannedFile;
  obligations: Map<string, Obligation>;
  aliases: Map<string, string>;
  findings: Finding[];
}

function resolveOb(ctx: ObligationCtx, name: string): Obligation | undefined {
  return ctx.obligations.get(ctx.aliases.get(name) ?? name);
}

function recordVarDeclObligations(ctx: ObligationCtx, stmt: AstNode): void {
  if (!Array.isArray(stmt.declarations)) return;
  const isUsingDecl = stmt.kind === "using" || stmt.kind === "await using";
  for (const decl of stmt.declarations) {
    if (!isAstNode(decl) || !isAstNode(decl.id) || decl.id.type !== "Identifier" || typeof decl.id.name !== "string") continue;
    if (isAstNode(decl.init) && decl.init.type === "Identifier" && typeof decl.init.name === "string") {
      const root = ctx.aliases.get(decl.init.name) ?? decl.init.name;
      if (ctx.obligations.has(root)) { ctx.aliases.set(decl.id.name, root); continue; }
    }
    const acq = isLinearAcquisition(isAstNode(decl.init) ? decl.init : null);
    if (!acq || isUsingDecl) continue;
    ctx.obligations.set(decl.id.name, {
      name: decl.id.name, kind: acq.kind, offset: decl.start ?? stmt.start ?? 0,
      isAbortController: acq.isAbortController, released: false, releasedInFinally: false,
      transferredOut: false, closedAtStmtIndex: -1,
    });
  }
}

function markCallUsage(
  ctx: ObligationCtx,
  cur: AstNode,
  opts: { insideFinally: boolean; topLevelStmtIdx: number },
): void {
  if (!cur.callee) return;
  if (!isAstNode(cur.callee)) return;
  const chain = getMemberChain(cur.callee);
  const parts = chain.split(".");
  if (parts.length === 2) {
    const [objName, method] = parts;
    const ob = objName ? resolveOb(ctx, objName) : undefined;
    if (ob && method) {
      if (RELEASE_METHODS.has(method)) {
        ob.released = true;
        if (opts.insideFinally) ob.releasedInFinally = true;
        if (opts.topLevelStmtIdx >= 0 && ob.closedAtStmtIndex < 0) ob.closedAtStmtIndex = opts.topLevelStmtIdx;
      } else if (opts.topLevelStmtIdx > ob.closedAtStmtIndex && ob.closedAtStmtIndex >= 0 && !ob.isAbortController) {
        push(ctx.findings, {
          file: ctx.file, offset: cur.start ?? 0, rule: "affine-use-after-close", severity: "error",
          message: `Linear handle '${ob.name}' used via '.${method}()' after it was already closed/released.`,
          fix: `Finish all operations on '${ob.name}' before closing it in a finally block.`,
        });
      }
    }
  }
  if ((chain === "fs.closeSync" || chain === "closeSync") && Array.isArray(cur.arguments)) {
    const first = isAstNode(cur.arguments[0]) ? cur.arguments[0] : null;
    const ob = first?.type === "Identifier" && typeof first.name === "string" ? resolveOb(ctx, first.name) : undefined;
    if (ob) {
      ob.released = true;
      if (opts.insideFinally) ob.releasedInFinally = true;
      if (opts.topLevelStmtIdx >= 0 && ob.closedAtStmtIndex < 0) ob.closedAtStmtIndex = opts.topLevelStmtIdx;
    }
  }
  if (Array.isArray(cur.arguments) && /\.(?:on|once|pipe|register|addCleanup|track)$/i.test(chain)) {
    for (const a of cur.arguments) {
      const ob = isAstNode(a) && a.type === "Identifier" && typeof a.name === "string" ? resolveOb(ctx, a.name) : undefined;
      if (ob) ob.transferredOut = true;
    }
  }
}

function markObligationUsage(
  ctx: ObligationCtx,
  node: AstNode,
  opts: { insideFinally: boolean; topLevelStmtIdx: number },
): void {
  walkAst(node, (cur) => {
    if (cur.type === "ReturnStatement" && isAstNode(cur.argument)) {
      walkAst(cur.argument, (r) => {
        if (r.type === "Identifier" && typeof r.name === "string") {
          const ob = resolveOb(ctx, r.name);
          if (ob) ob.transferredOut = true;
        }
      });
    }
    if (cur.type === "CallExpression") markCallUsage(ctx, cur, opts);
    if (cur.type === "MemberExpression" && !cur.computed && isAstNode(cur.object) && cur.object.type === "Identifier" && typeof cur.object.name === "string") {
      const ob = resolveOb(ctx, cur.object.name);
      const prop = isAstNode(cur.property) && typeof cur.property.name === "string" ? cur.property.name : "";
      if (ob && ob.isAbortController && prop === "signal") ob.released = true;
    }
  });
}

function checkTsFunctionObligations(fnNode: AstNode, file: ScannedFile, findings: Finding[]): void {
  if (!fnNode.body) return;
  const body = isAstNode(fnNode.body) && fnNode.body.type === "BlockStatement" ? fnNode.body : null;
  if (!body || !Array.isArray(body.body)) return;
  const ctx: ObligationCtx = { file, obligations: new Map(), aliases: new Map(), findings };
  for (let idx = 0; idx < body.body.length; idx++) {
    const stmt = body.body[idx];
    if (!isAstNode(stmt)) continue;
    if (stmt.type === "VariableDeclaration") { recordVarDeclObligations(ctx, stmt); continue; }
    if (stmt.type === "TryStatement") {
      if (isAstNode(stmt.block)) markObligationUsage(ctx, stmt.block, { insideFinally: false, topLevelStmtIdx: -1 });
      if (isAstNode(stmt.handler)) markObligationUsage(ctx, stmt.handler, { insideFinally: false, topLevelStmtIdx: -1 });
      if (isAstNode(stmt.finalizer)) markObligationUsage(ctx, stmt.finalizer, { insideFinally: true, topLevelStmtIdx: -1 });
    } else if (stmt.type === "IfStatement") {
      markObligationUsage(ctx, stmt, { insideFinally: false, topLevelStmtIdx: -1 });
    } else {
      markObligationUsage(ctx, stmt, { insideFinally: false, topLevelStmtIdx: idx });
    }
  }
  for (const ob of ctx.obligations.values()) {
    if (ob.transferredOut) continue;
    if (!ob.released) {
      push(findings, {
        file, offset: ob.offset, rule: "affine-unreleased-resource", severity: "warn",
        message: `Linear resource '${ob.name}' acquired via ${ob.kind}() is never closed, released, or returned (affine obligation leak).`,
        fix: `Close/release '${ob.name}' in a finally block (or declare with 'using' / return ownership explicitly).`,
      });
    } else if (!ob.isAbortController && !ob.releasedInFinally && body.body.length >= 3) {
      const hasThrowingBetween = body.body.some((s, i) => isAstNode(s) && i < ob.closedAtStmtIndex && (s.type === "ExpressionStatement" || s.type === "VariableDeclaration") && (s.start ?? 0) > ob.offset);
      if (hasThrowingBetween && ob.closedAtStmtIndex > 0) {
        push(findings, {
          file, offset: ob.offset, rule: "affine-unreleased-resource", severity: "warn",
          message: `Linear resource '${ob.name}' (${ob.kind}) is closed sequentially without try/finally — an intermediate exception leaks the handle.`,
          fix: `Wrap work on '${ob.name}' in try { ... } finally { ... } so release executes on every exit path.`,
        });
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
    push(findings, {
      file, offset: idx, rule: "affine-unreleased-resource", severity: "warn",
      message: `Python resource '${varName}' acquired outside 'with' and lacks guaranteed finally: close()/release().`,
      fix: `Use 'with ... as ${varName}:' or close '${varName}' inside a finally: block.`,
    });
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
