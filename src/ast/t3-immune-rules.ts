import type { ScannedFile } from "../discover.ts";
import { lineOf, maskCode } from "../test-lexical.ts";
import type { Finding } from "../types.ts";
import { type AstNode, getMemberChain, isAstNode, parseTsAst, walkAst } from "./ts-ast.ts";

const SH_PKILL_PATTERN = /\bpkill\s+-[a-zA-Z]*f\b|\bpgrep\b[^\n|]*\|\s*(?:xargs\s+)?kill\b/g;
const DRIZZLE_TS_NO_TZ = /\btimestamp\s*\(\s*["'][^"']+["']\s*\)/g;
const TEST_FRAME_WAIT = /\brequestAnimationFrame\s*\(|\baddEventListener\s*\(\s*["']transitionend["']/g;
const TEST_POLLING_LOOP = /\bwhile\s*\([^)\n]+\)\s*\{[^}]{0,260}\b(?:sleep|yieldNow|setTimeout)\s*\(/g;
const PY_SOURCE_INTROSPECTION = /\binspect\.getsource(?:lines)?\s*\(/g;
const JS_FN_TOSTRING_THEATER = /(?:Function\.prototype\.toString\.call\s*\(|\b([a-z_$][A-Za-z0-9_$]*)\.toString\s*\(\s*\))/g;
const NON_FN_TOSTRING_RECEIVER = /^(?:err|error|e|ex|url|uri|buf|buffer|val|value|num|n|id|count|total|sum|len|length|size|idx|index|i|j|k|x|y|z|str|text|body|out|stdout|stderr|res|result|raw|data|date|now|ts|time|path|file|dir|rel|abs|href|host|port|code|status|msg|message|name|key|token|hash|digest|hex|uuid|ver|version|re|regex|pattern|match|args|argv|cmd|line|src|source|content|json|xml|html|sql|query|params|searchParams|headers|response|request|req|big|bigint|bn|dec|decimal|amount|price|score|rate|pct|ms|sec|min|max|avg|stdoutText|stderrText)$/i;

function push(
  findings: Finding[],
  file: string,
  line: number,
  rule: string,
  category: Finding["category"],
  rung: Finding["rung"],
  severity: Finding["severity"],
  message: string,
  fix: string,
): void {
  findings.push({ id: `T3:${rule}:${file}:${line}`, rule, category, rung, severity, file, line, message, fix });
}

export function analyzeT3TestGuards(file: ScannedFile): Finding[] {
  const findings: Finding[] = [];
  const raw = file.content;
  if (file.language === "python") {
    const pyCode = maskCode(raw, "python");
    for (const m of raw.matchAll(PY_SOURCE_INTROSPECTION)) {
      const idx = m.index ?? 0;
      if (pyCode[idx] === " ") continue;
      push(
        findings, file.rel, lineOf(raw, idx), "test-source-introspection-theater", "cheat", "R2", "error",
        "Test introspects production source via inspect.getsource(), pinning syntax instead of testing runtime behavior.",
        "Assert observable inputs, outputs, and side effects rather than inspecting function source text.",
      );
    }
    return findings;
  }
  if (file.language !== "typescript" && file.language !== "javascript") return [];
  const code = maskCode(raw, file.language);

  if (/\b(?:toContain|toMatch|toBe|toEqual|includes|match|createHash)\b/.test(code)) {
    for (const m of raw.matchAll(JS_FN_TOSTRING_THEATER)) {
      const idx = m.index ?? 0;
      if (code[idx] === " ") continue;
      const recv = m[1] ?? "";
      if (recv && NON_FN_TOSTRING_RECEIVER.test(recv)) continue;
      const windowSlice = raw.slice(idx, Math.min(raw.length, idx + 220));
      if (/\b(?:createHash|sha256|md5)\b|["'`](?:===|!==|>=|<=|&&|\|\||return\b|if\s*\(|=>)/.test(windowSlice) || m[0].startsWith("Function.prototype")) {
        push(
          findings, file.rel, lineOf(raw, idx), "test-source-introspection-theater", "cheat", "R2", "error",
          "Test calls Function.toString() to assert source-code tokens or hashes instead of exercising runtime behavior.",
          "Write behavioral tests that invoke the function with representative inputs and assert outputs/state.",
        );
      }
    }
  }
  if (/\bcreateHash\s*\(/.test(code) && /\breadFileSync\s*\([^)]*(?:["'`]\.?\.?\/?src\/|["'`]src["'`])/.test(raw)) {
    const idx = raw.search(/\bcreateHash\s*\(/);
    push(
      findings, file.rel, lineOf(raw, Math.max(0, idx)), "test-source-introspection-theater", "cheat", "R2", "error",
      "Test hashes production source files from src/ via createHash(readFileSync(...)), which games mutation/canary checks without testing behavior.",
      "Remove source-file hash pinning and assert observable program behavior instead.",
    );
  }

  for (const m of raw.matchAll(TEST_FRAME_WAIT)) {
    const idx = m.index ?? 0;
    if (code[idx] === " ") continue;
    push(
      findings, file.rel, lineOf(raw, idx), "test-no-frame-waits", "test-smell", "R3", "warn",
      "Browser test waits on requestAnimationFrame or transitionend, which flakes under throttled/headless CI.",
      "Assert rendered DOM state via expect.element() or waitFor() instead of frame/transition events.",
    );
  }

  for (const m of code.matchAll(TEST_POLLING_LOOP)) {
    push(
      findings, file.rel, lineOf(raw, m.index ?? 0), "test-no-polling-loop", "test-smell", "R2", "warn",
      "Polling while-loop with sleep/yieldNow in test hides race conditions and burns CI time.",
      "Await a Deferred/Queue/persisted event or drain the async worker deterministically.",
    );
  }

  const isNodeTestOnly = /from\s+["']node:test["']/.test(raw) && !/\b(?:vitest|@jest|bun:test)\b/.test(raw);
  const ast = parseTsAst(file);
  if (ast) {
    walkAst(ast, (node) => {
      if (node.type === "CallExpression" && isAstNode(node.callee) && Array.isArray(node.arguments) && node.arguments.length >= 2) {
        const name = getMemberChain(node.callee);
        if (/^(?:test|it)(?:\.(?:concurrent|sequential|only|skip|todo|fails))?$/.test(name)) {
          const candidates = node.arguments.slice(1, 3);
          const hasTimeout = candidates.some((arg) => {
            const isNum = isAstNode(arg) && arg.type === "Literal" && typeof arg.value === "number" && arg.value >= 1000;
            const isObj = isAstNode(arg) && arg.type === "ObjectExpression" && Array.isArray(arg.properties) && arg.properties.some((p) => isAstNode(p) && isAstNode(p.key) && p.key.name === "timeout");
            return isNum || isObj;
          });
          if (hasTimeout) {
            push(
              findings, file.rel, lineOf(raw, node.start ?? 0), "test-no-per-test-timeout", "test-smell", "R2", "warn",
              "Per-test numeric timeout override masks slow or hanging tests instead of fixing the underlying wait.",
              "Remove custom per-test timeouts and let the suite default enforce fast deterministic execution.",
            );
          }
        }
      }

      if (!isNodeTestOnly && (node.type === "ForStatement" || node.type === "ForOfStatement" || node.type === "ForInStatement" || node.type === "WhileStatement")) {
        const body = isAstNode(node.body) ? node.body : null;
        if (!body) return;
        walkAst(body, (inner) => {
          if (inner.type === "CallExpression" && isAstNode(inner.callee)) {
            const name = getMemberChain(inner.callee);
            if (name === "test" || name === "it") {
              push(
                findings, file.rel, lineOf(raw, inner.start ?? 0), "test-no-test-in-loop", "test-smell", "R2", "warn",
                `Registering '${name}(...)' inside a loop breaks parameterized test filtering and isolation.`,
                `Use '${name}.each([...])' / table-driven test arrays instead of calling '${name}()' in a loop.`,
              );
              return false;
            }
          }
        });
      }
    });
  }

  return findings;
}

export function analyzeT3ProdGuards(file: ScannedFile, ast?: AstNode | null): Finding[] {
  const findings: Finding[] = [];
  const raw = file.content;

  if (/\.(?:sh|bash)$/i.test(file.rel)) {
    const lines = raw.split(/\r?\n/);
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i] ?? "";
      if (line.trim().startsWith("#")) continue;
      if (SH_PKILL_PATTERN.test(line)) {
        SH_PKILL_PATTERN.lastIndex = 0;
        push(
          findings, file.rel, i + 1, "sh-pkill-f-pattern-kill", "structure", "R0", "error",
          "Killing processes by argv pattern (pkill -f / pgrep | kill) can terminate unrelated agent/dev-server worktrees.",
          "Capture the exact child PID at spawn time and kill only that PID (or process group).",
        );
      }
    }
    return findings;
  }

  if ((file.language !== "typescript" && file.language !== "javascript") || file.isTest) return findings;
  const code = maskCode(raw, file.language);

  if (/\bpgTable\b|\bdrizzle-orm\/pg-core\b/.test(raw)) {
    for (const m of raw.matchAll(DRIZZLE_TS_NO_TZ)) {
      const idx = m.index ?? 0;
      if (code[idx] === " ") continue;
      push(
        findings, file.rel, lineOf(raw, idx), "drizzle-timestamp-missing-timezone", "structure", "R1", "warn",
        "Drizzle Postgres timestamp() without { withTimezone: true } stores timezone-naive timestamps and drifts across regions.",
        'Specify timestamp("col", { withTimezone: true }) for all Postgres timestamp columns.',
      );
    }
  }

  const parsed = ast ?? parseTsAst(file);
  if (!parsed) return findings;

  walkAst(parsed, (node) => {
    if (node.type === "CallExpression" && getMemberChain(isAstNode(node.callee) ? node.callee : null) === "useEffect" && Array.isArray(node.arguments)) {
      const cb = isAstNode(node.arguments[0]) ? node.arguments[0] : null;
      const cbBody = cb && isAstNode(cb.body) && cb.body.type === "BlockStatement" ? cb.body : null;
      if (cbBody && Array.isArray(cbBody.body)) {
        let hasExternalSync = false;
        let topLevelSetterOffset = -1;
        walkAst(cbBody, (inner) => {
          if (inner.type === "CallExpression" && isAstNode(inner.callee)) {
            const c = getMemberChain(inner.callee);
            if (/(?:fetch|addEventListener|subscribe|observe|setInterval|setTimeout|focus|scrollIntoView|dispatchEvent|postMessage|connect|open|matchMedia|getBoundingClientRect|getComputedStyle|getItem|setItem)$/i.test(c) || /^(?:localStorage|sessionStorage|window\.localStorage|window\.sessionStorage|navigator\.|document\.|indexedDB)\b/.test(c)) {
              hasExternalSync = true;
            }
          }
          if (inner.type === "NewExpression" && isAstNode(inner.callee)) {
            const c = getMemberChain(inner.callee);
            if (/^(?:WebSocket|EventSource|ResizeObserver|IntersectionObserver|MutationObserver|AbortController)$/.test(c)) {
              hasExternalSync = true;
            }
          }
        });
        for (const stmt of cbBody.body) {
          if (
            isAstNode(stmt) &&
            stmt.type === "ExpressionStatement" &&
            isAstNode(stmt.expression) &&
            stmt.expression.type === "CallExpression" &&
            isAstNode(stmt.expression.callee) &&
            stmt.expression.callee.type === "Identifier" &&
            typeof stmt.expression.callee.name === "string" &&
            /^set[A-Z]/.test(stmt.expression.callee.name)
          ) {
            topLevelSetterOffset = stmt.start ?? 0;
            break;
          }
        }
        if (topLevelSetterOffset >= 0 && !hasExternalSync) {
          push(
            findings, file.rel, lineOf(raw, topLevelSetterOffset), "react-no-unreasoned-state-sync", "structure", "R1", "warn",
            "useEffect synchronously calls setState without synchronizing an external system, causing extra render cascades.",
            "Derive the value during render or update state directly inside the triggering event handler.",
          );
        }
      }
    }

    if (node.type === "ForStatement" || node.type === "ForOfStatement" || node.type === "ForInStatement" || node.type === "WhileStatement") {
      const body = isAstNode(node.body) ? node.body : null;
      if (!body) return;
      walkAst(body, (inner) => {
        if (inner.type === "CallExpression" && isAstNode(inner.callee)) {
          const c = getMemberChain(inner.callee);
          if (c === "Schema.decodeUnknownSync" || c === "Schema.encodeSync" || c === "ajv.compile") {
            push(
              findings, file.rel, lineOf(raw, inner.start ?? 0), "perf-no-inline-schema-compile", "structure", "R1", "warn",
              `Compiling schema codec '${c}()' inside a loop repeatedly builds parser plans on every iteration.`,
              "Hoist the compiled schema decoder/validator to module scope outside the loop.",
            );
            return false;
          }
        }
      });
    }

    if (node.type === "CallExpression" && isAstNode(node.callee) && node.callee.type === "MemberExpression" && !node.callee.computed && Array.isArray(node.arguments) && node.arguments.length === 2) {
      const prop = isAstNode(node.callee.property) && typeof node.callee.property.name === "string" ? node.callee.property.name : "";
      const obj = getMemberChain(isAstNode(node.callee.object) ? node.callee.object : null);
      const arg0 = isAstNode(node.arguments[0]) ? node.arguments[0] : null;
      if ((prop === "slice" || prop === "substring") && arg0?.type === "Literal" && arg0.value === 0 && /(?:title|label|heading|excerpt|summary|preview|caption)$/i.test(obj)) {
        const ctx = raw.slice(Math.max(0, (node.start ?? 0) - 180), (node.end ?? 0) + 80);
        if (!/Array\.from|Intl\.Segmenter|\[\.\.\./.test(ctx)) {
          push(
            findings, file.rel, lineOf(raw, node.start ?? 0), "js-utf16-surrogate-slice-truncation", "structure", "R1", "warn",
            `Truncating display string '${obj}.${prop}(0, ...)' by UTF-16 code units splits emoji surrogate pairs.`,
            "Slice code points ([...str].slice(0, max).join('')) or Intl.Segmenter graphemes when truncating display text.",
          );
        }
      }
    }
  });

  return findings;
}
