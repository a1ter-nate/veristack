import type { ScannedFile } from "../discover.ts";
import { lineOf, maskCode } from "../test-lexical.ts";
import type { Finding } from "../types.ts";
import { type AstNode, getMemberChain, isAstNode, parseTsAst, walkAst } from "./ts-ast.ts";

const GO_ERR_TYPE_ASSERT = /\b([A-Za-z_][A-Za-z0-9_]*[Ee]rr[A-Za-z0-9_]*|err)\.\(\s*\*?[A-Za-z_][A-Za-z0-9_.]*(?:Error|Err)\b/g;
const GO_SLICE_LEN_PLUS = /\[len\(\s*([A-Za-z_][A-Za-z0-9_.]*)\s*\)\s*\+\s*[1-9]\d*\s*:/g;
const GO_UNIMPL_PANIC = /\bpanic\s*\(\s*["'](?:unimplemented|not implemented|todo|TODO)["']\s*\)/g;
const RUST_UNIMPL_MACRO = /\b(?:todo|unimplemented)!\s*\(/g;

const PY_EXCEPT_JSON_DECODE = /^\s*except\s+(?:\(\s*)?json\.JSONDecodeError\b([^:\n]*):/gm;
const PY_IPV6_HOST_FMT = /f["'][^"'\n]*\{[^}\n]*\.hostname[^}\n]*\}:/g;
const HTTP_DEL_CONTENT_TYPE = /(?:\bdelete\s+[A-Za-z0-9_$.]+\s*\[\s*["']content-type["']\s*\]|\.\s*(?:delete|Del)\s*\(\s*["']content-type["']\s*\))/gi;
const SH_BOOL_ENV_NONZERO = /\[\s+-n\s+["']?\$\{?[A-Z0-9_]*(?:REQUIRE|ENABLE|DISABLE|SKIP|ALLOW|FORCE|DEBUG|VERBOSE)[A-Z0-9_]*[^"'\s\]]*\}?["']?\s*\]/g;

function push(
  findings: Finding[],
  file: string,
  line: number,
  rule: string,
  rung: Finding["rung"],
  severity: Finding["severity"],
  message: string,
  fix: string,
): void {
  findings.push({ id: `BHR:${rule}:${file}:${line}`, rule, category: "structure", rung, severity, file, line, message, fix });
}

function analyzeTsReplayAst(file: ScannedFile, ast: AstNode, findings: Finding[]): void {
  walkAst(ast, (node) => {
    if (node.type === "IfStatement" && isAstNode(node.test) && node.test.type === "BinaryExpression" && node.test.operator === "in") {
      const left = isAstNode(node.test.left) ? node.test.left : null;
      const right = isAstNode(node.test.right) ? node.test.right : null;
      if (left?.type === "Literal" && typeof left.value === "string" && right?.type === "Identifier" && typeof right.name === "string" && isAstNode(node.consequent)) {
        const key = left.value;
        const obj = right.name;
        const bodyText = file.content.slice(node.consequent.start ?? 0, node.consequent.end ?? 0);
        const hasNullGuard =
          bodyText.includes(`${obj}.${key} != null`) ||
          bodyText.includes(`${obj}.${key} !== undefined`) ||
          bodyText.includes(`${obj}.${key} !== null`) ||
          bodyText.includes(`${obj}[`) && bodyText.includes("!= null");
        if (!hasNullGuard) {
          let hasUnsafeArithOrCall = false;
          walkAst(node.consequent, (cur) => {
            if (hasUnsafeArithOrCall) return false;
            if (cur.type === "BinaryExpression" || cur.type === "AssignmentExpression") {
              const op = typeof cur.operator === "string" ? cur.operator : "";
              if (/^[+\-*/%]=$|^[+\-*/%<>]$|^[<>]=$/.test(op)) {
                const seg = file.content.slice(cur.start ?? 0, cur.end ?? 0);
                if (seg.includes(`${obj}.${key}`)) hasUnsafeArithOrCall = true;
              }
            }
          });
          if (hasUnsafeArithOrCall) {
            push(
              findings, file.rel, lineOf(file.content, node.start ?? 0), "js-in-operator-guard-before-arith-or-deref", "R1", "warn",
              `'${key}' in ${obj} passes when { ${key}: undefined }, causing NaN/TypeError on arithmetic/deref inside the branch.`,
              `Guard with '${obj}.${key} != null' instead of ''${key}' in ${obj}'.`,
            );
          }
        }
      }
    }

    if (node.type === "TemplateLiteral" && Array.isArray(node.expressions) && Array.isArray(node.quasis)) {
      for (let i = 0; i < node.expressions.length; i++) {
        const expr = node.expressions[i];
        const nextQuasi = node.quasis[i + 1];
        if (!isAstNode(expr) || !isAstNode(nextQuasi) || typeof nextQuasi.value !== "object" || nextQuasi.value === null) continue;
        const chain = getMemberChain(expr);
        const rawNext = String((nextQuasi.value as { raw?: unknown }).raw ?? "");
        if (chain.endsWith(".hostname") && rawNext.startsWith(":")) {
          const start = Math.max(0, (node.start ?? 0) - 260);
          const ctx = file.content.slice(start, (node.end ?? 0) + 60);
          if (!/includes\s*\(\s*["']:["']\s*\)/.test(ctx)) {
            push(
              findings, file.rel, lineOf(file.content, node.start ?? 0), "http-ipv6-unbracketed-host-header", "R1", "warn",
              "Interpolating url.hostname with ':port' without bracketing IPv6 literals breaks IPv6 Host headers/URLs.",
              "Use url.host or bracket IPv6 hostnames containing ':' before appending ':port'.",
            );
          }
        }
      }
    }

    if (node.type === "FunctionDeclaration" || node.type === "FunctionExpression" || node.type === "ArrowFunctionExpression") {
      const body = isAstNode(node.body) ? node.body : null;
      if (!body) return;
      let checkedAborted = false;
      let listenerOffset = -1;
      let signalName = "";

      walkAst(body, (cur) => {
        if (cur !== body && (cur.type === "FunctionDeclaration" || cur.type === "FunctionExpression" || cur.type === "ArrowFunctionExpression")) {
          return false;
        }
        if (cur.type === "MemberExpression") {
          const ch = getMemberChain(cur);
          if (ch.endsWith(".aborted")) checkedAborted = true;
        }
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
        push(
          findings, file.rel, lineOf(file.content, listenerOffset), "js-abortsignal-listener-without-aborted-check", "R1", "warn",
          `Registering an 'abort' listener on '${signalName}' without first checking '${signalName}.aborted' hangs forever if already aborted.`,
          `Check 'if (${signalName}.aborted) ...' or call '${signalName}.throwIfAborted()' before addEventListener('abort', ...).`,
        );
      }
    }
  });
}

export function analyzeBlackHoleReplayGuards(file: ScannedFile, ast?: AstNode | null): Finding[] {
  const findings: Finding[] = [];
  const raw = file.content;

  if (/\.(?:sh|bash)$/i.test(file.rel)) {
    const lines = raw.split(/\r?\n/);
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i] ?? "";
      if (line.trim().startsWith("#")) continue;
      if (SH_BOOL_ENV_NONZERO.test(line)) {
        SH_BOOL_ENV_NONZERO.lastIndex = 0;
        push(
          findings, file.rel, i + 1, "sh-boolean-env-nonzero-trap", "R1", "warn",
          "Testing a boolean env flag with '[ -n \"${VAR:-}\" ]' evaluates 'VAR=false' as true.",
          'Compare explicitly against "true" (e.g. [ "${VAR:-false}" = "true" ]).',
        );
      }
    }
    return findings;
  }

  if (!file.language || file.isTest) return findings;
  const code = maskCode(raw, file.language);
  const cfgTestIdx = file.language === "rust" ? raw.search(/#\[cfg\(test\)\]/) : -1;
  const prodCode = cfgTestIdx >= 0 ? code.slice(0, cfgTestIdx) : code;
  const prodRaw = cfgTestIdx >= 0 ? raw.slice(0, cfgTestIdx) : raw;

  if (file.language === "typescript" || file.language === "javascript" || file.language === "go" || file.language === "python") {
    for (const m of prodRaw.matchAll(HTTP_DEL_CONTENT_TYPE)) {
      const idx = m.index ?? 0;
      if (prodCode[idx] === " ") continue;
      const win = prodRaw.slice(Math.max(0, idx - 120), idx + 320);
      if (/content-length/i.test(win)) continue;
      push(
        findings, file.rel, lineOf(raw, idx), "http-delete-content-type-without-content-length", "R1", "warn",
        "Deleting the 'content-type' header when re-serializing a request body without clearing 'content-length' leaves a stale byte length.",
        "Delete or recompute 'content-length' alongside 'content-type' when forwarding or re-encoding bodies.",
      );
    }
  }

  if (file.language === "go") {
    for (const m of prodCode.matchAll(GO_ERR_TYPE_ASSERT)) {
      push(
        findings, file.rel, lineOf(raw, m.index ?? 0), "go-error-type-assert-not-as", "R1", "error",
        `Direct error type assertion (${m[0].trim()}) fails silently on wrapped errors (%w).`,
        "Use errors.As(err, &target) instead of direct type assertions on error values.",
      );
    }

    for (const m of prodCode.matchAll(GO_SLICE_LEN_PLUS)) {
      const idx = m.index ?? 0;
      const prefix = m[1] ?? "";
      if (!prefix) continue;
      const before = prodCode.slice(Math.max(0, idx - 260), idx);
      if (before.includes(`> len(${prefix})`) || before.includes(`>= len(${prefix}) +`) || before.includes(`>= len(${prefix})+`)) {
        continue;
      }
      if (before.includes("HasPrefix(") || before.includes(`>= len(${prefix})`)) {
        push(
          findings, file.rel, lineOf(raw, idx), "go-slice-len-plus-offset-oob", "R1", "error",
          `Slicing at [len(${prefix})+k:] after HasPrefix/'>=' panics with slice bounds out of range when lengths are equal.`,
          `Verify len(s) > len(${prefix}) (or use strings.TrimPrefix + separator check) before slicing past len(${prefix}).`,
        );
      }
    }

    for (const m of prodRaw.matchAll(GO_UNIMPL_PANIC)) {
      const idx = m.index ?? 0;
      if (prodCode[idx] === " ") continue;
      push(
        findings, file.rel, lineOf(raw, idx), "no-unimplemented-panic-in-prod", "R0", "error",
        `Production Go code contains '${m[0].trim()}', which crashes at runtime if reached.`,
        "Return an explicit typed error or complete the implementation before shipping.",
      );
    }
    return findings;
  }

  if (file.language === "rust") {
    for (const m of prodCode.matchAll(RUST_UNIMPL_MACRO)) {
      push(
        findings, file.rel, lineOf(raw, m.index ?? 0), "no-unimplemented-panic-in-prod", "R0", "error",
        `Production Rust code contains '${m[0].trim()})', which panics at runtime if reached.`,
        "Return a typed Err(...) variant or complete the implementation.",
      );
    }
    return findings;
  }

  if (file.language === "python") {
    for (const m of prodCode.matchAll(PY_EXCEPT_JSON_DECODE)) {
      const clause = m[1] ?? "";
      if (/\bRecursionError\b/.test(clause)) continue;
      push(
        findings, file.rel, lineOf(raw, m.index ?? 0), "py-json-loads-missing-recursion-error", "R1", "warn",
        "Catching json.JSONDecodeError without RecursionError lets deeply nested JSON payloads crash the handler.",
        "Catch (json.JSONDecodeError, RecursionError) when parsing untrusted JSON payloads.",
      );
    }

    for (const m of prodRaw.matchAll(PY_IPV6_HOST_FMT)) {
      const idx = m.index ?? 0;
      if (prodCode[idx] === " ") continue;
      const win = prodRaw.slice(Math.max(0, idx - 260), idx + 120);
      if (/IPv6Address|\b\[.*host|":" in\b/i.test(win)) continue;
      push(
        findings, file.rel, lineOf(raw, idx), "http-ipv6-unbracketed-host-header", "R1", "warn",
        "Formatting parsed.hostname with ':port' without bracketing IPv6 literals produces invalid RFC 3986 Host headers/URLs.",
        "Bracket IPv6 literals (f'[{host}]:{port}') when ':' is present or ipaddress detects IPv6Address.",
      );
    }
    return findings;
  }

  if (file.language === "typescript" || file.language === "javascript") {
    const parsed = ast ?? parseTsAst(file);
    if (parsed) analyzeTsReplayAst(file, parsed, findings);
  }

  return findings;
}
