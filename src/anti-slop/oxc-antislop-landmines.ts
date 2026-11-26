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

function pushFinding(
  findings: Finding[],
  file: ScannedFile,
  offset: number,
  rule: string,
  category: Finding["category"],
  rung: Finding["rung"],
  severity: Finding["severity"],
  message: string,
  fix: string,
): void {
  const line = lineOf(file.content, offset);
  findings.push({
    id: `AS:${rule}:${file.rel}:${line}`,
    rule,
    category,
    rung,
    severity,
    file: file.rel,
    line,
    message,
    fix,
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
  if ((file.language === "typescript" || file.language === "javascript") && ast) {
    const dir = path.posix.dirname(file.rel.replace(/\\/g, "/"));
    const checkSpec = (spec: string, offset: number): void => {
      if (!spec.startsWith(".")) return;
      if (!spec.includes("/internal/") && !spec.endsWith("/internal")) return;
      const resolved = path.posix.normalize(path.posix.join(dir, spec));
      const owner = violatesInternalBoundary(file.rel, resolved);
      if (owner) {
        pushFinding(
          findings,
          file,
          offset,
          "no-cross-feature-internal-import",
          "structure",
          "R1",
          "error",
          `Cross-feature import '${spec}' reaches into '${owner}/internal/' from outside '${owner}/'.`,
          `Import from '${owner}' public entry point instead of reaching into '${owner}/internal/'.`,
        );
      }
    };
    walkAst(ast, (node) => {
      if (
        (node.type === "ImportDeclaration" ||
          node.type === "ExportNamedDeclaration" ||
          node.type === "ExportAllDeclaration") &&
        isAstNode(node.source) &&
        node.source.type === "Literal" &&
        typeof node.source.value === "string"
      ) {
        checkSpec(node.source.value, node.start ?? 0);
      } else if (
        node.type === "CallExpression" &&
        isAstNode(node.callee) &&
        node.callee.type === "Identifier" &&
        node.callee.name === "require" &&
        Array.isArray(node.arguments) &&
        isAstNode(node.arguments[0]) &&
        node.arguments[0].type === "Literal" &&
        typeof node.arguments[0].value === "string"
      ) {
        checkSpec(node.arguments[0].value, node.start ?? 0);
      }
    });
  } else if (file.language === "python") {
    for (const m of code.matchAll(IMPORT_SPEC_PY)) {
      const mod = m[1] ?? m[2] ?? "";
      if (!mod.includes(".internal.") && !mod.endsWith(".internal")) continue;
      if (mod.startsWith(".")) continue;
      const targetRel = mod.replace(/\./g, "/");
      const owner = violatesInternalBoundary(file.rel, targetRel);
      if (owner) {
        pushFinding(
          findings,
          file,
          m.index ?? 0,
          "no-cross-feature-internal-import",
          "structure",
          "R1",
          "error",
          `Cross-package Python import '${mod}' reaches into '${owner}/internal/' from outside '${owner}/'.`,
          `Import from '${owner.replace(/\//g, ".")}' public API instead of internal modules.`,
        );
      }
    }
  }
}

export function analyzeUniversalAntiSlopProd(file: ScannedFile, ast: AstNode | null): Finding[] {
  if (!file.language || file.isTest || file.rel.endsWith(".pyi") || file.rel.endsWith(".d.ts")) return [];
  const findings: Finding[] = [];
  const raw = file.content;
  const code = maskCode(raw, file.language);

  checkInternalBoundaryImports(file, code, ast, findings);

  if (ast && (file.language === "typescript" || file.language === "javascript")) {
    let dictCount = 0;
    let objParamCount = 0;

    walkAst(ast, (node) => {
      if (node.type === "CallExpression" && isAstNode(node.callee) && node.callee.type === "MemberExpression") {
        const obj = isAstNode(node.callee.object) ? node.callee.object : null;
        const prop = isAstNode(node.callee.property) ? node.callee.property : null;
        if (
          obj?.type === "Identifier" &&
          obj.name === "Reflect" &&
          prop?.type === "Identifier" &&
          (prop.name === "apply" || prop.name === "get" || prop.name === "set")
        ) {
          pushFinding(
            findings,
            file,
            node.start ?? 0,
            "no-reflect-dynamic-invoke",
            "structure",
            "R0",
            "error",
            `Dynamic Reflect.${prop.name}() bypasses static typing and hides property/call contracts.`,
            "Use direct typed function calls or explicit property access / Map lookups.",
          );
        }
      }

      if (file.language === "typescript") {
        if (node.type === "TSTypeAliasDeclaration" && isAstNode(node.typeAnnotation)) {
          if (node.typeAnnotation.type === "TSUnknownKeyword" || node.typeAnnotation.type === "TSAnyKeyword") {
            const name = isAstNode(node.id) && typeof node.id.name === "string" ? node.id.name : "alias";
            pushFinding(
              findings,
              file,
              node.start ?? 0,
              "no-unknown-type-alias",
              "structure",
              "R1",
              "warn",
              `Type alias '${name}' masks '${node.typeAnnotation.type === "TSAnyKeyword" ? "any" : "unknown"}' behind a domain-sounding name.`,
              "Model the actual discriminated union, interface, or schema-inferred type instead of aliasing unknown/any.",
            );
          }
        }

        if (node.type === "TSTypeReference" && isAstNode(node.typeName) && node.typeName.type === "Identifier") {
          const refName = typeof node.typeName.name === "string" ? node.typeName.name : "";
          if (refName === "Record" && isAstNode(node.typeArguments) && Array.isArray(node.typeArguments.params)) {
            const valType = node.typeArguments.params[1];
            if (isAstNode(valType) && valType.type === "TSAnyKeyword" && ++dictCount <= 5) {
              pushFinding(
                findings,
                file,
                node.start ?? 0,
                "no-unsafe-dictionary-type",
                "structure",
                "R1",
                "warn",
                "Record<string, any> disables value type checking across every lookup.",
                "Use an explicit interface, Map<K, V>, or Record<K, unknown> parsed at the boundary.",
              );
            }
          }
          if ((refName === "Object" || refName === "Function") && ++objParamCount <= 5) {
            pushFinding(
              findings,
              file,
              node.start ?? 0,
              "no-object-type-escape",
              "structure",
              "R1",
              "warn",
              `Boxed '${refName}' type accepts almost any value and disables structural type checking.`,
              refName === "Function"
                ? "Declare an explicit callable signature '(arg: A) => B' instead of 'Function'."
                : "Declare an explicit interface, record type, or generic constraint instead of 'Object'.",
            );
          }
        }
      }
    });
  }

  const dictRe =
    file.language === "csharp"
      ? UNSAFE_DICT_CS
      : file.language === "python"
        ? UNSAFE_DICT_PY
        : file.language === "go"
          ? UNSAFE_DICT_GO
          : null;
  if (dictRe) {
    let count = 0;
    for (const m of code.matchAll(dictRe)) {
      if (++count > 5) break;
      pushFinding(
        findings,
        file,
        m.index ?? 0,
        "no-unsafe-dictionary-type",
        "structure",
        "R1",
        "warn",
        `Untyped string dictionary '${m[0].trim()}' discards value contracts.`,
        "Replace with a typed struct/record/TypedDict/dataclass or a strongly typed map value.",
      );
    }
  }

  return findings;
}

export function analyzeUniversalLandminesTest(file: ScannedFile, code: string, ast: AstNode | null): Finding[] {
  if (!file.language || !file.isTest) return [];
  const findings: Finding[] = [];

  for (const m of code.matchAll(UNSIGNALED_POLL_LOOP)) {
    pushFinding(
      findings,
      file,
      m.index ?? 0,
      "no-unsignaled-poll",
      "test-smell",
      "R0",
      "error",
      "Clock-driven busy-poll loop in test races wall-clock deadlines and causes CI flakes.",
      "Await an explicit completion signal, promise, channel, or web-first locator assertion.",
    );
  }
  if (file.language === "python") {
    for (const m of code.matchAll(UNSIGNALED_POLL_PY)) {
      pushFinding(
        findings,
        file,
        m.index ?? 0,
        "no-unsignaled-poll",
        "test-smell",
        "R0",
        "error",
        "Clock-driven busy-poll loop in Python test causes flaky timeouts.",
        "Wait on an asyncio.Event, threading.Event, or explicit queue completion instead.",
      );
    }
  }
  if (file.language === "typescript" || file.language === "javascript") {
    for (const m of code.matchAll(UNSIGNALED_POLL_EXPECT)) {
      pushFinding(
        findings,
        file,
        m.index ?? 0,
        "no-unsignaled-poll",
        "test-smell",
        "R0",
        "error",
        "Polling mock call state with expect.poll masks race conditions.",
        "Await the observable async operation or explicit event directly.",
      );
    }
    for (const m of code.matchAll(STRICT_MSW_UNCONFIGURED)) {
      pushFinding(
        findings,
        file,
        m.index ?? 0,
        "strict-msw",
        "test-smell",
        "R0",
        "warn",
        "MSW server.listen() called without { onUnhandledRequest: 'error' }; unexpected HTTP calls pass silently.",
        "Pass server.listen({ onUnhandledRequest: 'error' }) so unhandled network calls fail immediately.",
      );
    }
    for (const m of code.matchAll(COLD_IMPORT_IN_TEST)) {
      if (/\bresetModules\b/.test(m[0])) continue;
      pushFinding(
        findings,
        file,
        m.index ?? 0,
        "no-cold-import-in-test",
        "test-smell",
        "R0",
        "warn",
        "Dynamic await import() inside a test body pays cold-module startup cost inside the test timer.",
        "Move static imports to module scope so test bodies measure only behavior.",
      );
    }

    if (ast && Array.isArray(ast.body)) {
      for (const stmt of ast.body) {
        if (!isAstNode(stmt) || stmt.type !== "VariableDeclaration" || !Array.isArray(stmt.declarations)) continue;
        for (const decl of stmt.declarations) {
          if (!isAstNode(decl) || !isAstNode(decl.init)) continue;
          const initSrc = file.content.slice(decl.init.start ?? 0, decl.init.end ?? 0);
          if (/\bAbortSignal\.timeout\s*\(|\bnew\s+AbortController\s*\(/.test(initSrc)) {
            pushFinding(
              findings,
              file,
              decl.start ?? 0,
              "no-shared-abort-signal",
              "test-smell",
              "R0",
              "warn",
              "Module-scoped AbortSignal/AbortController shares timeout and cancellation state across tests.",
              "Create a fresh AbortController or AbortSignal.timeout() inside each test case.",
            );
          }
        }
      }
    }
  }

  return findings;
}
