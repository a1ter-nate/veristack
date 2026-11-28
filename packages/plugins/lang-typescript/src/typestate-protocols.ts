import fs from "node:fs";
import path from "node:path";
import { lineOf, type DiscoveredRepo, type Finding, type ScannedFile } from "@veristack/plugin";
import { type AstNode, getMemberChain, isAstNode, parseTsAst, walkAst } from "./ts-ast.ts";

export interface TypestateProtocolDef {
  id: string;
  constructors: readonly string[];
  initial: string;
  terminal: readonly string[];
  transitions: Readonly<Record<string, Readonly<Record<string, string>>>>;
}

export interface TypestateProtocolFile {
  schemaVersion: 1;
  protocols: readonly TypestateProtocolDef[];
}

interface TrackedHandle {
  name: string;
  protocol: TypestateProtocolDef;
  state: string;
  offset: number;
  transferredOut: boolean;
}

function getCalleeName(node: AstNode | null): string {
  if (!node) return "";
  let cur: AstNode = node;
  for (let i = 0; i < 6 && cur.type === "AwaitExpression" && isAstNode(cur.argument); i++) cur = cur.argument;
  if (cur.type === "CallExpression" && isAstNode(cur.callee)) return getMemberChain(cur.callee);
  if (cur.type === "NewExpression" && isAstNode(cur.callee)) return `new ${getMemberChain(cur.callee)}`;
  return "";
}

export function loadTypestateProtocols(repoRoot: string): TypestateProtocolDef[] {
  const filePath = path.join(repoRoot, ".verification", "protocols.json");
  if (!fs.existsSync(filePath)) return [];
  let parsed: unknown;
  try { parsed = JSON.parse(fs.readFileSync(filePath, "utf8")); } catch { return []; }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return [];
  const rawList = (parsed as Record<string, unknown>).protocols;
  if (!Array.isArray(rawList)) return [];
  const out: TypestateProtocolDef[] = [];
  for (const item of rawList) {
    if (!item || typeof item !== "object" || Array.isArray(item)) continue;
    const rec = item as Record<string, unknown>;
    if (typeof rec.id !== "string" || typeof rec.initial !== "string" || !Array.isArray(rec.constructors) || !Array.isArray(rec.terminal)) continue;
    if (!rec.transitions || typeof rec.transitions !== "object" || Array.isArray(rec.transitions)) continue;
    out.push({
      id: rec.id,
      constructors: rec.constructors.filter((c): c is string => typeof c === "string"),
      initial: rec.initial,
      terminal: rec.terminal.filter((t): t is string => typeof t === "string"),
      transitions: rec.transitions as Record<string, Record<string, string>>,
    });
  }
  return out;
}

function checkFunctionTypestate(
  fnNode: AstNode,
  file: ScannedFile,
  ctorMap: ReadonlyMap<string, TypestateProtocolDef>,
  findings: Finding[],
): void {
  const body = isAstNode(fnNode.body) && fnNode.body.type === "BlockStatement" ? fnNode.body : null;
  if (!body || !Array.isArray(body.body)) return;
  const handles = new Map<string, TrackedHandle>();
  for (const stmt of body.body) {
    if (!isAstNode(stmt)) continue;
    if (stmt.type === "VariableDeclaration" && Array.isArray(stmt.declarations)) {
      for (const decl of stmt.declarations) {
        if (!isAstNode(decl) || !isAstNode(decl.id) || decl.id.type !== "Identifier" || typeof decl.id.name !== "string") continue;
        const callee = getCalleeName(isAstNode(decl.init) ? decl.init : null);
        const proto = ctorMap.get(callee);
        if (proto) handles.set(decl.id.name, { name: decl.id.name, protocol: proto, state: proto.initial, offset: decl.start ?? 0, transferredOut: false });
      }
      continue;
    }
    walkAst(stmt, (cur) => {
      if (cur.type === "ReturnStatement" && isAstNode(cur.argument)) {
        walkAst(cur.argument, (r) => {
          if (r.type === "Identifier" && typeof r.name === "string") {
            const h = handles.get(r.name);
            if (h) h.transferredOut = true;
          }
        });
      }
      if (cur.type !== "CallExpression" || !isAstNode(cur.callee)) return;
      const parts = getMemberChain(cur.callee).split(".");
      if (parts.length !== 2) return;
      const [objName, method] = parts;
      const h = objName ? handles.get(objName) : undefined;
      if (!h || !method) return;
      const allProtocolMethods = new Set<string>();
      for (const map of Object.values(h.protocol.transitions)) for (const m of Object.keys(map)) allProtocolMethods.add(m);
      if (!allProtocolMethods.has(method)) return;
      const nextState = h.protocol.transitions[h.state]?.[method];
      if (!nextState) {
        const line = lineOf(file.content, cur.start ?? 0);
        findings.push({
          id: `TS:invalid:${file.rel}:${line}:${h.name}`, rule: "typestate-invalid-transition", category: "structure", rung: "R1",
          severity: "error", soundness: "incorrectness-witness", file: file.rel, line,
          message: `Protocol '${h.protocol.id}' forbids '.${method}()' on '${h.name}' in state '${h.state}' (Strom & Yemini typestate violation).`,
          fix: `Advance '${h.name}' through valid transitions from '${h.state}' (${Object.keys(h.protocol.transitions[h.state] ?? {}).join(", ") || "terminal"}) before calling '.${method}()'.`,
        });
        return;
      }
      h.state = nextState;
    });
  }
  for (const h of handles.values()) {
    if (h.transferredOut || h.protocol.terminal.includes(h.state)) continue;
    const line = lineOf(file.content, h.offset);
    findings.push({
      id: `TS:unterm:${file.rel}:${line}:${h.name}`, rule: "typestate-unterminated-protocol", category: "structure", rung: "R1",
      severity: "warn", soundness: "incorrectness-witness", file: file.rel, line,
      message: `Protocol handle '${h.name}' ('${h.protocol.id}') ends in non-terminal state '${h.state}' (expected: ${h.protocol.terminal.join(" | ")}).`,
      fix: `Drive '${h.name}' to a terminal state (${h.protocol.terminal.join(" | ")}) in a try/finally block or return ownership.`,
    });
  }
}

export function analyzeTypestateProtocols(repo: DiscoveredRepo, explicitProtocols?: readonly TypestateProtocolDef[]): Finding[] {
  if (!repo.root) throw new Error("repo.root is required.");
  const protocols = explicitProtocols ?? loadTypestateProtocols(repo.root);
  if (protocols.length === 0) return [];
  const ctorMap = new Map<string, TypestateProtocolDef>();
  for (const p of protocols) for (const c of p.constructors) ctorMap.set(c, p);
  const findings: Finding[] = [];
  for (const file of repo.files) {
    if (file.isTest || file.isStub || (file.language !== "typescript" && file.language !== "javascript")) continue;
    const ast = parseTsAst(file);
    if (!ast) continue;
    walkAst(ast, (node) => {
      if (node.type === "FunctionDeclaration" || node.type === "FunctionExpression" || node.type === "ArrowFunctionExpression") {
        checkFunctionTypestate(node, file, ctorMap, findings);
      }
    });
  }
  return findings;
}
