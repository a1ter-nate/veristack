import path from "node:path";
import { type AstNode, isAstNode, walkAst } from "../ast/ts-ast.ts";
import type { ScannedFile } from "../discover.ts";
import { lineOf, maskCode } from "../test-lexical.ts";
import type { Finding } from "../types.ts";

const UNSAFE_DICT_CS = /\b(?:I?Dictionary|ConcurrentDictionary)\s*<\s*string\s*,\s*(?:object|dynamic)\s*>/g;
const UNSAFE_DICT_PY = /\b(?:dict|Dict|Mapping)\s*\[\s*str\s*,\s*Any\s*\]/g;
const UNSAFE_DICT_GO = /\bmap\s*\[\s*string\s*\]\s*(?:any|interface\s*\{\s*\})/g;

const IMPORT_SPEC_PY = /^\s*(?:from\s+([A-Za-z0-9_.]+)\s+import|import\s+([A-Za-z0-9_.]+))/gm;

const UNSIGNALED_POLL_LOOP =
  /\bwhile\s*\(\s*(?:Date\.now\s*\(\s*\)|performance\.now\s*\(\s*\)|Stopwatch\.GetTimestamp|[A-Za-z_][A-Za-z0-9_.]*\.Elapsed(?:Milliseconds)?)\s*</g;
const UNSIGNALED_POLL_PY = /\bwhile\s+(?:time\.time|time\.monotonic)\s*\(\s*\)\s*</g;
const UNSIGNALED_POLL_EXPECT = /\bexpect\.poll\s*\(\s*\(\s*\)\s*=>\s*[A-Za-z_$][A-Za-z0-9_$.]*\.mock\b/g;

const COLD_IMPORT_IN_TEST = /\b(?:it|test)\s*\([^{]*\{[\s\S]{0,400}?\bawait\s+import\s*\(/g;
const STRICT_MSW_UNCONFIGURED = /\b(?:server|mswServer)\s*\.\s*listen\s*\(\s*\)/g;

interface LandmineFindingSpec {
  file: ScannedFile;
  offset: number;
  rule: string;
  category: Finding["category"];
  rung: Finding["rung"];
  severity: Finding["severity"];
  message: string;
  fix: string;
}

function pushFinding(findings: Finding[], spec: LandmineFindingSpec): void {
  const line = lineOf(spec.file.content, spec.offset);
  findings.push({
    id: `AS:${spec.rule}:${spec.file.rel}:${line}`,
    rule: spec.rule,
    category: spec.category,
    rung: spec.rung,
    severity: spec.severity,
    file: spec.file.rel,
    line,
    message: spec.message,
    fix: spec.fix,
  });
}

function violatesInternalBoundary(fromRel: string, targetRel: string): string | null {
  const normFrom = fromRel.replace(/\\/g, "/");
  const normTarget = targetRel.replace(/\\/g, "/");
  const parts = normTarget.split("/");
  const internalIdx = parts.lastIndexOf("internal");
  if (internalIdx <= 0) return null;
  const ownerPrefix = parts.slice(0, internalIdx).join("/");
  if (normFrom === ownerPrefix || normFrom.startsWith(`${ownerPrefix}/`)) return null;
  return ownerPrefix;
}

function checkInternalBoundaryImports(file: ScannedFile, code: string, ast: AstNode | null, findings: Finding[]): void {
  if (!file.content) return;
  if ((file.language === "typescript" || file.language === "javascript") && ast) {
    const dir = path.posix.dirname(file.rel.replace(/\\/g, "/"));
    const checkSpec = (spec: string, offset: number): void => {
      if (!spec.startsWith(".")) return;
      if (!spec.includes("/internal/") && !spec.endsWith("/internal")) return;
      const resolved = path.posix.normalize(path.posix.join(dir, spec));
      const owner = violatesInternalBoundary(file.rel, resolved);
      if (owner) {
        pushFinding(findings, {
          file, offset, rule: "no-cross-feature-internal-import", category: "structure", rung: "R1", severity: "error",
          message: `Cross-feature import '${spec}' reaches into '${owner}/internal/' from outside '${owner}/'.`,
          fix: `Import from '${owner}' public entry point instead of reaching into '${owner}/internal/'.`,
        });
      }
    };
    walkAst(ast, (node) => {
      if (
        (node.type === "ImportDeclaration" || node.type === "ExportNamedDeclaration" || node.type === "ExportAllDeclaration") &&
        isAstNode(node.source) && node.source.type === "Literal" && typeof node.source.value === "string"
      ) {
        checkSpec(node.source.value, node.start ?? 0);
      } else if (
        node.type === "CallExpression" && isAstNode(node.callee) && node.callee.type === "Identifier" && node.callee.name === "require" &&
        Array.isArray(node.arguments) && isAstNode(node.arguments[0]) && node.arguments[0].type === "Literal" && typeof node.arguments[0].value === "string"
      ) {
        checkSpec(node.arguments[0].value, node.start ?? 0);
      }
    });
    return;
  }
  if (file.language !== "python") return;
  for (const m of code.matchAll(IMPORT_SPEC_PY)) {
    const mod = m[1] ?? m[2] ?? "";
    if ((!mod.includes(".internal.") && !mod.endsWith(".internal")) || mod.startsWith(".")) continue;
    const owner = violatesInternalBoundary(file.rel, mod.replace(/\./g, "/"));
    if (owner) {
      pushFinding(findings, {
        file, offset: m.index ?? 0, rule: "no-cross-feature-internal-import", category: "structure", rung: "R1", severity: "error",
        message: `Cross-package Python import '${mod}' reaches into '${owner}/internal/' from outside '${owner}/'.`,
        fix: `Import from '${owner.replace(/\//g, ".")}' public API instead of internal modules.`,
      });
    }
  }
}

function checkTsTypeEscapeNode(
  file: ScannedFile,
  node: AstNode,
  counts: { dict: number; obj: number },
  findings: Finding[],
): void {
  if (!node.type) return;
  if (node.type === "TSTypeAliasDeclaration" && isAstNode(node.typeAnnotation)) {
    if (node.typeAnnotation.type === "TSUnknownKeyword" || node.typeAnnotation.type === "TSAnyKeyword") {
      const name = isAstNode(node.id) && typeof node.id.name === "string" ? node.id.name : "alias";
      pushFinding(findings, {
        file, offset: node.start ?? 0, rule: "no-unknown-type-alias", category: "structure", rung: "R1", severity: "warn",
        message: `Type alias '${name}' masks '${node.typeAnnotation.type === "TSAnyKeyword" ? "any" : "unknown"}' behind a domain-sounding name.`,
        fix: "Model the actual discriminated union, interface, or schema-inferred type instead of aliasing unknown/any.",
      });
    }
    return;
  }
  if (node.type !== "TSTypeReference" || !isAstNode(node.typeName) || node.typeName.type !== "Identifier") return;
  const refName = typeof node.typeName.name === "string" ? node.typeName.name : "";
  if (refName === "Record" && isAstNode(node.typeArguments) && Array.isArray(node.typeArguments.params)) {
    const valType = node.typeArguments.params[1];
    if (isAstNode(valType) && valType.type === "TSAnyKeyword" && ++counts.dict <= 5) {
      pushFinding(findings, {
        file, offset: node.start ?? 0, rule: "no-unsafe-dictionary-type", category: "structure", rung: "R1", severity: "warn",
        message: "Record<string, any> disables value type checking across every lookup.",
        fix: "Use an explicit interface, Map<K, V>, or Record<K, unknown> parsed at the boundary.",
      });
    }
  }
  if ((refName === "Object" || refName === "Function") && ++counts.obj <= 5) {
    pushFinding(findings, {
      file, offset: node.start ?? 0, rule: "no-object-type-escape", category: "structure", rung: "R1", severity: "warn",
      message: `Boxed '${refName}' type accepts almost any value and disables structural type checking.`,
      fix: refName === "Function"
        ? "Declare an explicit callable signature '(arg: A) => B' instead of 'Function'."
        : "Declare an explicit interface, record type, or generic constraint instead of 'Object'.",
    });
  }
}

function checkTsAstAntiSlop(file: ScannedFile, ast: AstNode, findings: Finding[]): void {
  const counts = { dict: 0, obj: 0 };
  walkAst(ast, (node) => {
    if (node.type === "CallExpression" && isAstNode(node.callee) && node.callee.type === "MemberExpression") {
      const obj = isAstNode(node.callee.object) ? node.callee.object : null;
      const prop = isAstNode(node.callee.property) ? node.callee.property : null;
      if (obj?.type === "Identifier" && obj.name === "Reflect" && prop?.type === "Identifier" && (prop.name === "apply" || prop.name === "get" || prop.name === "set")) {
        pushFinding(findings, {
          file, offset: node.start ?? 0, rule: "no-reflect-dynamic-invoke", category: "structure", rung: "R0", severity: "error",
          message: `Dynamic Reflect.${prop.name}() bypasses static typing and hides property/call contracts.`,
          fix: "Use direct typed function calls or explicit property access / Map lookups.",
        });
      }
    }
    if (file.language === "typescript") checkTsTypeEscapeNode(file, node, counts, findings);
  });
}

export function analyzeUniversalAntiSlopProd(file: ScannedFile, ast: AstNode | null): Finding[] {
  if (!file.language || file.isTest || file.rel.endsWith(".pyi") || file.rel.endsWith(".d.ts")) return [];
  const findings: Finding[] = [];
  const code = maskCode(file.content, file.language);
  checkInternalBoundaryImports(file, code, ast, findings);
  if (ast && (file.language === "typescript" || file.language === "javascript")) checkTsAstAntiSlop(file, ast, findings);
  const dictRe =
    file.language === "csharp" ? UNSAFE_DICT_CS : file.language === "python" ? UNSAFE_DICT_PY : file.language === "go" ? UNSAFE_DICT_GO : null;
  if (dictRe) {
    let count = 0;
    for (const m of code.matchAll(dictRe)) {
      if (++count > 5) break;
      pushFinding(findings, {
        file, offset: m.index ?? 0, rule: "no-unsafe-dictionary-type", category: "structure", rung: "R1", severity: "warn",
        message: `Untyped string dictionary '${m[0].trim()}' discards value contracts.`,
        fix: "Replace with a typed struct/record/TypedDict/dataclass or a strongly typed map value.",
      });
    }
  }
  return findings;
}

function checkSharedAbortSignals(file: ScannedFile, ast: AstNode, findings: Finding[]): void {
  if (!Array.isArray(ast.body)) return;
  for (const stmt of ast.body) {
    if (!isAstNode(stmt) || stmt.type !== "VariableDeclaration" || !Array.isArray(stmt.declarations)) continue;
    for (const decl of stmt.declarations) {
      if (!isAstNode(decl) || !isAstNode(decl.init)) continue;
      const initSrc = file.content.slice(decl.init.start ?? 0, decl.init.end ?? 0);
      if (/\bAbortSignal\.timeout\s*\(|\bnew\s+AbortController\s*\(/.test(initSrc)) {
        pushFinding(findings, {
          file, offset: decl.start ?? 0, rule: "no-shared-abort-signal", category: "test-smell", rung: "R0", severity: "warn",
          message: "Module-scoped AbortSignal/AbortController shares timeout and cancellation state across tests.",
          fix: "Create a fresh AbortController or AbortSignal.timeout() inside each test case.",
        });
      }
    }
  }
}

function checkTsTestLandmines(file: ScannedFile, code: string, ast: AstNode | null, findings: Finding[]): void {
  if (!code) return;
  for (const m of code.matchAll(UNSIGNALED_POLL_EXPECT)) {
    pushFinding(findings, {
      file, offset: m.index ?? 0, rule: "no-unsignaled-poll", category: "test-smell", rung: "R0", severity: "error",
      message: "Polling mock call state with expect.poll masks race conditions.",
      fix: "Await the observable async operation or explicit event directly.",
    });
  }
  for (const m of code.matchAll(STRICT_MSW_UNCONFIGURED)) {
    pushFinding(findings, {
      file, offset: m.index ?? 0, rule: "strict-msw", category: "test-smell", rung: "R0", severity: "warn",
      message: "MSW server.listen() called without { onUnhandledRequest: 'error' }; unexpected HTTP calls pass silently.",
      fix: "Pass server.listen({ onUnhandledRequest: 'error' }) so unhandled network calls fail immediately.",
    });
  }
  for (const m of code.matchAll(COLD_IMPORT_IN_TEST)) {
    if (/\bresetModules\b/.test(m[0])) continue;
    pushFinding(findings, {
      file, offset: m.index ?? 0, rule: "no-cold-import-in-test", category: "test-smell", rung: "R0", severity: "warn",
      message: "Dynamic await import() inside a test body pays cold-module startup cost inside the test timer.",
      fix: "Move static imports to module scope so test bodies measure only behavior.",
    });
  }
  if (ast) checkSharedAbortSignals(file, ast, findings);
}

export function analyzeUniversalLandminesTest(file: ScannedFile, code: string, ast: AstNode | null): Finding[] {
  if (!file.language || !file.isTest) return [];
  const findings: Finding[] = [];
  for (const m of code.matchAll(UNSIGNALED_POLL_LOOP)) {
    pushFinding(findings, {
      file, offset: m.index ?? 0, rule: "no-unsignaled-poll", category: "test-smell", rung: "R0", severity: "error",
      message: "Clock-driven busy-poll loop in test races wall-clock deadlines and causes CI flakes.",
      fix: "Await an explicit completion signal, promise, channel, or web-first locator assertion.",
    });
  }
  if (file.language === "python") {
    for (const m of code.matchAll(UNSIGNALED_POLL_PY)) {
      pushFinding(findings, {
        file, offset: m.index ?? 0, rule: "no-unsignaled-poll", category: "test-smell", rung: "R0", severity: "error",
        message: "Clock-driven busy-poll loop in Python test causes flaky timeouts.",
        fix: "Wait on an asyncio.Event, threading.Event, or explicit queue completion instead.",
      });
    }
  }
  if (file.language === "typescript" || file.language === "javascript") checkTsTestLandmines(file, code, ast, findings);
  return findings;
}
