import type { ScannedFile } from "@veristack/plugin";
import { lineOf, maskCode } from "@veristack/plugin";
import type { Finding } from "@veristack/plugin";
import { type AstNode, getMemberChain, isAstNode, parseTsAst, walkAst } from "./ts-ast.ts";

const GO_ERR_TYPE_ASSERT = /\b([A-Za-z_][A-Za-z0-9_]*[Ee]rr[A-Za-z0-9_]*|err)\.\(\s*\*?[A-Za-z_][A-Za-z0-9_.]*(?:Error|Err)\b/g;
const GO_SLICE_LEN_PLUS = /\[len\(\s*([A-Za-z_][A-Za-z0-9_.]*)\s*\)\s*\+\s*[1-9]\d*\s*:/g;
const GO_UNIMPL_PANIC = /\bpanic\s*\(\s*["'](?:unimplemented|not implemented|todo|TODO)["']\s*\)/g;
const RUST_UNIMPL_MACRO = /\b(?:todo|unimplemented)!\s*\(/g;

const PY_EXCEPT_JSON_DECODE = /^\s*except\s+(?:\(\s*)?json\.JSONDecodeError\b([^:\n]*):/gm;
const PY_IPV6_HOST_FMT = /f["'][^"'\n]*\{[^}\n]*\.hostname[^}\n]*\}:/g;
const HTTP_DEL_CONTENT_TYPE = /(?:\bdelete\s+[A-Za-z0-9_$.]+\s*\[\s*["']content-type["']\s*\]|\.\s*(?:delete|Del)\s*\(\s*["']content-type["']\s*\))/gi;
const SH_BOOL_ENV_NONZERO = /\[\s+-n\s+["']?\$\{?[A-Z0-9_]*(?:REQUIRE|ENABLE|DISABLE|SKIP|ALLOW|FORCE|DEBUG|VERBOSE)[A-Z0-9_]*[^"'\s\]]*\}?["']?\s*\]/g;

interface ReplayFindingSpec {
  file: string;
  line: number;
  rule: string;
  rung: Finding["rung"];
  severity: Finding["severity"];
  message: string;
  fix: string;
}

function push(findings: Finding[], spec: ReplayFindingSpec): void {
  findings.push({ id: `BHR:${spec.rule}:${spec.file}:${spec.line}`, category: "structure", ...spec });
}

function checkInOperatorArithGuard(file: ScannedFile, node: AstNode, findings: Finding[]): void {
  if (node.type !== "IfStatement" || !isAstNode(node.test) || node.test.type !== "BinaryExpression" || node.test.operator !== "in") return;
  const left = isAstNode(node.test.left) ? node.test.left : null;
  const right = isAstNode(node.test.right) ? node.test.right : null;
  if (left?.type !== "Literal" || typeof left.value !== "string" || right?.type !== "Identifier" || typeof right.name !== "string" || !isAstNode(node.consequent)) return;
  const key = left.value;
  const obj = right.name;
  const bodyText = file.content.slice(node.consequent.start ?? 0, node.consequent.end ?? 0);
  const hasNullGuard =
    bodyText.includes(`${obj}.${key} != null`) ||
    bodyText.includes(`${obj}.${key} !== undefined`) ||
    bodyText.includes(`${obj}.${key} !== null`) ||
    (bodyText.includes(`${obj}[`) && bodyText.includes("!= null"));
  if (hasNullGuard) return;
  let hasUnsafeArithOrCall = false;
  walkAst(node.consequent, (cur) => {
    if (hasUnsafeArithOrCall) return false;
    if (cur.type === "BinaryExpression" || cur.type === "AssignmentExpression") {
      const op = typeof cur.operator === "string" ? cur.operator : "";
      if (/^[+\-*/%]=$|^[+\-*/%<>]$|^[<>]=$/.test(op) && file.content.slice(cur.start ?? 0, cur.end ?? 0).includes(`${obj}.${key}`)) {
        hasUnsafeArithOrCall = true;
      }
    }
  });
  if (hasUnsafeArithOrCall) {
    push(findings, {
      file: file.rel, line: lineOf(file.content, node.start ?? 0), rule: "js-in-operator-guard-before-arith-or-deref", rung: "R1", severity: "warn",
      message: `'${key}' in ${obj} passes when { ${key}: undefined }, causing NaN/TypeError on arithmetic/deref inside the branch.`,
      fix: `Guard with '${obj}.${key} != null' instead of ''${key}' in ${obj}'.`,
    });
  }
}

function checkIpv6TemplateHost(file: ScannedFile, node: AstNode, findings: Finding[]): void {
  if (node.type !== "TemplateLiteral" || !Array.isArray(node.expressions) || !Array.isArray(node.quasis)) return;
  for (let i = 0; i < node.expressions.length; i++) {
    const expr = node.expressions[i];
    const nextQuasi = node.quasis[i + 1];
    if (!isAstNode(expr) || !isAstNode(nextQuasi) || typeof nextQuasi.value !== "object" || nextQuasi.value === null) continue;
    const chain = getMemberChain(expr);
    const rawNext = String((nextQuasi.value as { raw?: unknown }).raw ?? "");
    if (!chain.endsWith(".hostname") || !rawNext.startsWith(":")) continue;
    if (/^:\s/.test(rawNext)) continue;
    const beforeTmpl = file.content.slice(Math.max(0, (node.start ?? 0) - 80), node.start ?? 0);
    const tmplRaw = file.content.slice(node.start ?? 0, node.end ?? 0);
    if (/(?:new\s+\w*Error|console\.\w+|logger\.\w+)\s*\([^)]*$/.test(beforeTmpl) && !/(?:https?|wss?):\/\/|\bhost\b/i.test(tmplRaw)) continue;
    const ctx = file.content.slice(Math.max(0, (node.start ?? 0) - 260), (node.end ?? 0) + 60);
    if (!/includes\s*\(\s*["']:["']\s*\)/.test(ctx)) {
      push(findings, {
        file: file.rel, line: lineOf(file.content, node.start ?? 0), rule: "http-ipv6-unbracketed-host-header", rung: "R1", severity: "warn",
        message: "Interpolating url.hostname with ':port' without bracketing IPv6 literals breaks IPv6 Host headers/URLs.",
        fix: "Use url.host or bracket IPv6 hostnames containing ':' before appending ':port'.",
      });
    }
  }
}

function checkAbortSignalListener(file: ScannedFile, node: AstNode, findings: Finding[]): void {
  if (node.type !== "FunctionDeclaration" && node.type !== "FunctionExpression" && node.type !== "ArrowFunctionExpression") return;
  const body = isAstNode(node.body) ? node.body : null;
  if (!body) return;
  let checkedAborted = false;
  let listenerOffset = -1;
  let signalName = "";
  walkAst(body, (cur) => {
    if (cur !== body && (cur.type === "FunctionDeclaration" || cur.type === "FunctionExpression" || cur.type === "ArrowFunctionExpression")) return false;
    if (cur.type === "MemberExpression" && getMemberChain(cur).endsWith(".aborted")) checkedAborted = true;
    if (cur.type === "CallExpression" && isAstNode(cur.callee)) {
      const ch = getMemberChain(cur.callee);
      if (ch.endsWith(".throwIfAborted")) checkedAborted = true;
      if (ch.endsWith(".addEventListener") && Array.isArray(cur.arguments)) {
        const evArg = isAstNode(cur.arguments[0]) ? cur.arguments[0] : null;
        if (evArg?.type === "Literal" && evArg.value === "abort" && /signal/i.test(ch)) {
          listenerOffset = cur.start ?? 0;
          signalName = ch.replace(/\.addEventListener$/, "");
        }
      }
    }
  });
  if (listenerOffset >= 0 && !checkedAborted) {
    push(findings, {
      file: file.rel, line: lineOf(file.content, listenerOffset), rule: "js-abortsignal-listener-without-aborted-check", rung: "R1", severity: "warn",
      message: `Registering an 'abort' listener on '${signalName}' without first checking '${signalName}.aborted' hangs forever if already aborted.`,
      fix: `Check 'if (${signalName}.aborted) ...' or call '${signalName}.throwIfAborted()' before addEventListener('abort', ...).`,
    });
  }
}

function analyzeTsReplayAst(file: ScannedFile, ast: AstNode, findings: Finding[]): void {
  walkAst(ast, (node) => {
    checkInOperatorArithGuard(file, node, findings);
    checkIpv6TemplateHost(file, node, findings);
    checkAbortSignalListener(file, node, findings);
  });
}

function checkGoReplayGuards(file: ScannedFile, prodCode: string, findings: Finding[]): void {
  if (!prodCode) return;
  const raw = file.content;
  for (const m of prodCode.matchAll(GO_ERR_TYPE_ASSERT)) {
    push(findings, {
      file: file.rel, line: lineOf(raw, m.index ?? 0), rule: "go-error-type-assert-not-as", rung: "R1", severity: "error",
      message: `Direct error type assertion (${m[0].trim()}) fails silently on wrapped errors (%w).`,
      fix: "Use errors.As(err, &target) instead of direct type assertions on error values.",
    });
  }
  for (const m of prodCode.matchAll(GO_SLICE_LEN_PLUS)) {
    const idx = m.index ?? 0;
    const prefix = m[1] ?? "";
    if (!prefix) continue;
    const before = prodCode.slice(Math.max(0, idx - 260), idx);
    if (before.includes(`> len(${prefix})`) || before.includes(`>= len(${prefix}) +`) || before.includes(`>= len(${prefix})+`)) continue;
    if (before.includes("HasPrefix(") || before.includes(`>= len(${prefix})`)) {
      push(findings, {
        file: file.rel, line: lineOf(raw, idx), rule: "go-slice-len-plus-offset-oob", rung: "R1", severity: "error",
        message: `Slicing at [len(${prefix})+k:] after HasPrefix/'>=' panics with slice bounds out of range when lengths are equal.`,
        fix: `Verify len(s) > len(${prefix}) (or use strings.TrimPrefix + separator check) before slicing past len(${prefix}).`,
      });
    }
  }
  for (const m of raw.matchAll(GO_UNIMPL_PANIC)) {
    const idx = m.index ?? 0;
    if (prodCode[idx] === " ") continue;
    push(findings, {
      file: file.rel, line: lineOf(raw, idx), rule: "no-unimplemented-panic-in-prod", rung: "R0", severity: "error",
      message: `Production Go code contains '${m[0].trim()}', which crashes at runtime if reached.`,
      fix: "Return an explicit typed error or complete the implementation before shipping.",
    });
  }
}

function checkPythonReplayGuards(file: ScannedFile, prodCode: string, findings: Finding[]): void {
  if (!prodCode) return;
  const raw = file.content;
  for (const m of prodCode.matchAll(PY_EXCEPT_JSON_DECODE)) {
    if (/\bRecursionError\b/.test(m[1] ?? "")) continue;
    push(findings, {
      file: file.rel, line: lineOf(raw, m.index ?? 0), rule: "py-json-loads-missing-recursion-error", rung: "R1", severity: "warn",
      message: "Catching json.JSONDecodeError without RecursionError lets deeply nested JSON payloads crash the handler.",
      fix: "Catch (json.JSONDecodeError, RecursionError) when parsing untrusted JSON payloads.",
    });
  }
  for (const m of raw.matchAll(PY_IPV6_HOST_FMT)) {
    const idx = m.index ?? 0;
    if (prodCode[idx] === " ") continue;
    if (/IPv6Address|\b\[.*host|":" in\b/i.test(raw.slice(Math.max(0, idx - 260), idx + 120))) continue;
    push(findings, {
      file: file.rel, line: lineOf(raw, idx), rule: "http-ipv6-unbracketed-host-header", rung: "R1", severity: "warn",
      message: "Formatting parsed.hostname with ':port' without bracketing IPv6 literals produces invalid RFC 3986 Host headers/URLs.",
      fix: "Bracket IPv6 literals (f'[{host}]:{port}') when ':' is present or ipaddress detects IPv6Address.",
    });
  }
}

export function analyzeBlackHoleReplayGuards(file: ScannedFile, ast?: AstNode | null): Finding[] {
  const findings: Finding[] = [];
  const raw = file.content;
  if (/\.(?:sh|bash)$/i.test(file.rel)) {
    const lines = raw.split(/\r?\n/);
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i] ?? "";
      if (!line.trim().startsWith("#") && SH_BOOL_ENV_NONZERO.test(line)) {
        SH_BOOL_ENV_NONZERO.lastIndex = 0;
        push(findings, {
          file: file.rel, line: i + 1, rule: "sh-boolean-env-nonzero-trap", rung: "R1", severity: "warn",
          message: "Testing a boolean env flag with '[ -n \"${VAR:-}\" ]' evaluates 'VAR=false' as true.",
          fix: 'Compare explicitly against "true" (e.g. [ "${VAR:-false}" = "true" ]).',
        });
      }
    }
    return findings;
  }
  if (!file.language || file.isTest) return findings;
  const prodCode = maskCode(raw, file.language, true);
  if (file.language === "typescript" || file.language === "javascript" || file.language === "go" || file.language === "python") {
    for (const m of raw.matchAll(HTTP_DEL_CONTENT_TYPE)) {
      const idx = m.index ?? 0;
      if (prodCode[idx] === " " || /content-length/i.test(raw.slice(Math.max(0, idx - 120), idx + 320))) continue;
      push(findings, {
        file: file.rel, line: lineOf(raw, idx), rule: "http-delete-content-type-without-content-length", rung: "R1", severity: "warn",
        message: "Deleting the 'content-type' header when re-serializing a request body without clearing 'content-length' leaves a stale byte length.",
        fix: "Delete or recompute 'content-length' alongside 'content-type' when forwarding or re-encoding bodies.",
      });
    }
  }
  if (file.language === "go") { checkGoReplayGuards(file, prodCode, findings); return findings; }
  if (file.language === "rust") {
    for (const m of prodCode.matchAll(RUST_UNIMPL_MACRO)) {
      push(findings, {
        file: file.rel, line: lineOf(raw, m.index ?? 0), rule: "no-unimplemented-panic-in-prod", rung: "R0", severity: "error",
        message: `Production Rust code contains '${m[0].trim()})', which panics at runtime if reached.`,
        fix: "Return a typed Err(...) variant or complete the implementation.",
      });
    }
    return findings;
  }
  if (file.language === "python") { checkPythonReplayGuards(file, prodCode, findings); return findings; }
  if (file.language === "typescript" || file.language === "javascript") {
    const parsed = ast ?? parseTsAst(file);
    if (parsed) analyzeTsReplayAst(file, parsed, findings);
  }
  return findings;
}
