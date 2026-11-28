import type { ScannedFile } from "@veristack/plugin";
import { lineOf, maskCode } from "@veristack/plugin";
import type { Finding } from "@veristack/plugin";
import { type AstNode, getMemberChain, isAstNode, parseTsAst, walkAst } from "./ts-ast.ts";

const SH_PKILL_PATTERN = /\bpkill\s+-[a-zA-Z]*f\b|\bpgrep\b[^\n|]*\|\s*(?:xargs\s+)?kill\b/g;
const DRIZZLE_TS_NO_TZ = /\btimestamp\s*\(\s*["'][^"']+["']\s*\)/g;
const TEST_FRAME_WAIT = /\brequestAnimationFrame\s*\(|\baddEventListener\s*\(\s*["']transitionend["']/g;
const TEST_POLLING_LOOP = /\bwhile\s*\([^)\n]+\)\s*\{[^}]{0,260}\b(?:sleep|yieldNow|setTimeout)\s*\(/g;
const PY_SOURCE_INTROSPECTION = /\binspect\.getsource(?:lines)?\s*\(/g;
const JS_FN_TOSTRING_THEATER = /(?:Function\.prototype\.toString\.call\s*\(|\bString\s*\(\s*([a-z_$][A-Za-z0-9_$]*)\s*\)|\b([a-z_$][A-Za-z0-9_$]*)\.toString\s*\(\s*\))/g;
const NON_FN_TOSTRING_RECEIVER = /^(?:err|error|e|ex|url|uri|buf|buffer|val|value|num|n|id|count|total|sum|len|length|size|idx|index|i|j|k|x|y|z|str|text|body|out|stdout|stderr|res|result|raw|data|date|now|ts|timestamp|epoch|time|path|file|dir|rel|abs|href|host|port|code|status|msg|message|name|key|token|hash|digest|hex|uuid|ver|version|re|regex|pattern|match|args|argv|cmd|line|src|source|content|json|xml|html|sql|query|params|searchParams|headers|response|request|req|big|bigint|bn|dec|decimal|amount|price|score|rate|pct|ms|sec|min|max|avg|stdoutText|stderrText|pid|uid|gid|seq|offset|limit|page|row|col|label|title|tag|mode|kind|type|delay|timeout|duration|elapsed)$/i;

interface T3FindingSpec {
  file: string;
  line: number;
  rule: string;
  category: Finding["category"];
  rung: Finding["rung"];
  severity: Finding["severity"];
  message: string;
  fix: string;
}

function push(findings: Finding[], spec: T3FindingSpec): void {
  findings.push({ id: `T3:${spec.rule}:${spec.file}:${spec.line}`, ...spec });
}

function checkTsTestAstGuards(file: ScannedFile, raw: string, findings: Finding[]): void {
  const isNodeTestOnly = /from\s+["']node:test["']/.test(raw) && !/\b(?:vitest|@jest|bun:test)\b/.test(raw);
  const ast = parseTsAst(file);
  if (!ast) return;
  walkAst(ast, (node) => {
    if (node.type === "CallExpression" && isAstNode(node.callee) && Array.isArray(node.arguments) && node.arguments.length >= 2) {
      const isDirectTestCallee =
        node.callee.type === "Identifier" ||
        (node.callee.type === "MemberExpression" && isAstNode(node.callee.object) && node.callee.object.type === "Identifier");
      const name = isDirectTestCallee ? getMemberChain(node.callee) : "";
      if (/^(?:test|it)(?:\.(?:concurrent|sequential|only|skip|todo|fails))?$/.test(name)) {
        const isIntegrationOrSubprocess =
          /(?:integration|e2e|smoke|contract)/i.test(file.rel) ||
          /\b(?:spawnSync|execFile|Testcontainers|playwright|puppeteer|new\s+Database)\b/.test(raw);
        const timeoutArg = node.arguments.slice(1, 3).find((arg) => {
          const isNum = isAstNode(arg) && arg.type === "Literal" && typeof arg.value === "number" && arg.value >= 1000;
          const isObj = isAstNode(arg) && arg.type === "ObjectExpression" && Array.isArray(arg.properties) && arg.properties.some((p) => isAstNode(p) && isAstNode(p.key) && p.key.name === "timeout");
          return isNum || isObj;
        });
        if (timeoutArg && !isIntegrationOrSubprocess) {
          push(findings, {
            file: file.rel, line: lineOf(raw, (isAstNode(timeoutArg) ? timeoutArg.start : undefined) ?? node.start ?? 0), rule: "test-no-per-test-timeout", category: "test-smell", rung: "R2", severity: "warn",
            message: "Per-test numeric timeout override masks slow or hanging tests instead of fixing the underlying wait.",
            fix: "Remove custom per-test timeouts and let the suite default enforce fast deterministic execution.",
          });
        }
      }
    }
    if (!isNodeTestOnly && (node.type === "ForStatement" || node.type === "ForOfStatement" || node.type === "ForInStatement" || node.type === "WhileStatement")) {
      const rightName = node.type === "ForOfStatement" && isAstNode(node.right) && node.right.type === "Identifier" && typeof node.right.name === "string" ? node.right.name : "";
      const isNamedCasesTable = /(?:cases|table|rows|fixtures|scenarios|vectors|matrix|specs|examples|inputs)/i.test(rightName);
      const body = isAstNode(node.body) ? node.body : null;
      if (!body) return;
      walkAst(body, (inner) => {
        if (inner.type === "CallExpression" && isAstNode(inner.callee) && inner.callee.type === "Identifier") {
          const name = typeof inner.callee.name === "string" ? inner.callee.name : "";
          const firstArg = Array.isArray(inner.arguments) && isAstNode(inner.arguments[0]) ? inner.arguments[0] : null;
          if (isNamedCasesTable && firstArg && firstArg.type !== "Literal") return;
          if (name === "test" || name === "it") {
            push(findings, {
              file: file.rel, line: lineOf(raw, inner.start ?? 0), rule: "test-no-test-in-loop", category: "test-smell", rung: "R2", severity: "warn",
              message: `Registering '${name}(...)' inside a loop breaks parameterized test filtering and isolation.`,
              fix: `Use '${name}.each([...])' / table-driven test arrays instead of calling '${name}()' in a loop.`,
            });
            return false;
          }
        }
      });
    }
  });
}

export function analyzeT3TestGuards(file: ScannedFile): Finding[] {
  const findings: Finding[] = [];
  const raw = file.content;
  if (file.language === "python") {
    const pyCode = maskCode(raw, "python");
    for (const m of raw.matchAll(PY_SOURCE_INTROSPECTION)) {
      const idx = m.index ?? 0;
      if (pyCode[idx] === " ") continue;
      push(findings, {
        file: file.rel, line: lineOf(raw, idx), rule: "test-source-introspection-theater", category: "cheat", rung: "R2", severity: "error",
        message: "Test introspects production source via inspect.getsource(), pinning syntax instead of testing runtime behavior.",
        fix: "Assert observable inputs, outputs, and side effects rather than inspecting function source text.",
      });
    }
    return findings;
  }
  if (file.language !== "typescript" && file.language !== "javascript") return [];
  const code = maskCode(raw, file.language);
  if (/\b(?:toContain|toMatch|toBe|toEqual|includes|match|createHash)\b/.test(code)) {
    for (const m of raw.matchAll(JS_FN_TOSTRING_THEATER)) {
      const idx = m.index ?? 0;
      if (code[idx] === " ") continue;
      const recv = m[1] ?? m[2] ?? "";
      if (recv && NON_FN_TOSTRING_RECEIVER.test(recv)) continue;
      const windowSlice = raw.slice(idx, Math.min(raw.length, idx + 220));
      if (/\b(?:createHash|sha256|md5)\b|["'`](?:===|!==|>=|<=|&&|\|\||return\b|if\s*\(|=>)/.test(windowSlice) || m[0].startsWith("Function.prototype")) {
        push(findings, {
          file: file.rel, line: lineOf(raw, idx), rule: "test-source-introspection-theater", category: "cheat", rung: "R2", severity: "error",
          message: "Test calls Function.toString() to assert source-code tokens or hashes instead of exercising runtime behavior.",
          fix: "Write behavioral tests that invoke the function with representative inputs and assert outputs/state.",
        });
      }
    }
  }
  if (/\bcreateHash\s*\(/.test(code) && /\breadFileSync\s*\([^)]*(?:["'`]\.?\.?\/?src\/|["'`]src["'`])/.test(raw)) {
    push(findings, {
      file: file.rel, line: lineOf(raw, Math.max(0, raw.search(/\bcreateHash\s*\(/))), rule: "test-source-introspection-theater", category: "cheat", rung: "R2", severity: "error",
      message: "Test hashes production source files from src/ via createHash(readFileSync(...)), which games mutation/canary checks without testing behavior.",
      fix: "Remove source-file hash pinning and assert observable program behavior instead.",
    });
  }
  for (const m of raw.matchAll(TEST_FRAME_WAIT)) {
    const idx = m.index ?? 0;
    if (code[idx] === " ") continue;
    push(findings, {
      file: file.rel, line: lineOf(raw, idx), rule: "test-no-frame-waits", category: "test-smell", rung: "R3", severity: "warn",
      message: "Browser test waits on requestAnimationFrame or transitionend, which flakes under throttled/headless CI.",
      fix: "Assert rendered DOM state via expect.element() or waitFor() instead of frame/transition events.",
    });
  }
  for (const m of code.matchAll(TEST_POLLING_LOOP)) {
    push(findings, {
      file: file.rel, line: lineOf(raw, m.index ?? 0), rule: "test-no-polling-loop", category: "test-smell", rung: "R2", severity: "warn",
      message: "Polling while-loop with sleep/yieldNow in test hides race conditions and burns CI time.",
      fix: "Await a Deferred/Queue/persisted event or drain the async worker deterministically.",
    });
  }
  checkTsTestAstGuards(file, raw, findings);
  return findings;
}

function checkReactEffectStateSync(file: ScannedFile, raw: string, node: AstNode, findings: Finding[]): void {
  if (!node.type) return;
  if (node.type !== "CallExpression" || getMemberChain(isAstNode(node.callee) ? node.callee : null) !== "useEffect" || !Array.isArray(node.arguments)) return;
  const cb = isAstNode(node.arguments[0]) ? node.arguments[0] : null;
  const cbBody = cb && isAstNode(cb.body) && cb.body.type === "BlockStatement" ? cb.body : null;
  if (!cbBody || !Array.isArray(cbBody.body)) return;
  let hasExternalSync = false;
  walkAst(cbBody, (inner) => {
    if (inner.type === "CallExpression" && isAstNode(inner.callee)) {
      const c = getMemberChain(inner.callee);
      if (/(?:fetch|addEventListener|subscribe|observe|setInterval|setTimeout|focus|scrollIntoView|dispatchEvent|postMessage|connect|open|matchMedia|getBoundingClientRect|getComputedStyle|getItem|setItem)$/i.test(c) || /^(?:localStorage|sessionStorage|window\.localStorage|window\.sessionStorage|navigator\.|document\.|indexedDB)\b/.test(c)) {
        hasExternalSync = true;
      }
    }
    if (inner.type === "NewExpression" && isAstNode(inner.callee) && /^(?:WebSocket|EventSource|ResizeObserver|IntersectionObserver|MutationObserver|AbortController)$/.test(getMemberChain(inner.callee))) {
      hasExternalSync = true;
    }
  });
  let topLevelSetterOffset = -1;
  for (const stmt of cbBody.body) {
    if (isAstNode(stmt) && stmt.type === "ExpressionStatement" && isAstNode(stmt.expression) && stmt.expression.type === "CallExpression" && isAstNode(stmt.expression.callee) && stmt.expression.callee.type === "Identifier" && typeof stmt.expression.callee.name === "string" && /^set[A-Z]/.test(stmt.expression.callee.name)) {
      topLevelSetterOffset = stmt.start ?? 0;
      break;
    }
  }
  if (topLevelSetterOffset >= 0 && !hasExternalSync) {
    push(findings, {
      file: file.rel, line: lineOf(raw, topLevelSetterOffset), rule: "react-no-unreasoned-state-sync", category: "structure", rung: "R1", severity: "warn",
      message: "useEffect synchronously calls setState without synchronizing an external system, causing extra render cascades.",
      fix: "Derive the value during render or update state directly inside the triggering event handler.",
    });
  }
}

function checkLoopSchemaCompileAndSlice(file: ScannedFile, raw: string, node: AstNode, findings: Finding[]): void {
  if (node.type === "ForStatement" || node.type === "ForOfStatement" || node.type === "ForInStatement" || node.type === "WhileStatement") {
    const body = isAstNode(node.body) ? node.body : null;
    if (!body) return;
    walkAst(body, (inner) => {
      if (inner.type === "CallExpression" && isAstNode(inner.callee)) {
        const c = getMemberChain(inner.callee);
        if (c === "Schema.decodeUnknownSync" || c === "Schema.encodeSync" || c === "ajv.compile") {
          push(findings, {
            file: file.rel, line: lineOf(raw, inner.start ?? 0), rule: "perf-no-inline-schema-compile", category: "structure", rung: "R1", severity: "warn",
            message: `Compiling schema codec '${c}()' inside a loop repeatedly builds parser plans on every iteration.`,
            fix: "Hoist the compiled schema decoder/validator to module scope outside the loop.",
          });
          return false;
        }
      }
    });
    return;
  }
  if (node.type === "CallExpression" && isAstNode(node.callee) && node.callee.type === "MemberExpression" && !node.callee.computed && Array.isArray(node.arguments) && node.arguments.length === 2) {
    const prop = isAstNode(node.callee.property) && typeof node.callee.property.name === "string" ? node.callee.property.name : "";
    const obj = getMemberChain(isAstNode(node.callee.object) ? node.callee.object : null);
    const arg0 = isAstNode(node.arguments[0]) ? node.arguments[0] : null;
    if ((prop === "slice" || prop === "substring") && arg0?.type === "Literal" && arg0.value === 0 && /(?:title|label|heading|excerpt|summary|preview|caption)$/i.test(obj)) {
      if (!/Array\.from|Intl\.Segmenter|\[\.\.\./.test(raw.slice(Math.max(0, (node.start ?? 0) - 180), (node.end ?? 0) + 80))) {
        push(findings, {
          file: file.rel, line: lineOf(raw, node.start ?? 0), rule: "js-utf16-surrogate-slice-truncation", category: "structure", rung: "R1", severity: "warn",
          message: `Truncating display string '${obj}.${prop}(0, ...)' by UTF-16 code units splits emoji surrogate pairs.`,
          fix: "Slice code points ([...str].slice(0, max).join('')) or Intl.Segmenter graphemes when truncating display text.",
        });
      }
    }
  }
}

export function analyzeT3ProdGuards(file: ScannedFile, ast?: AstNode | null): Finding[] {
  const findings: Finding[] = [];
  const raw = file.content;
  if (/\.(?:sh|bash)$/i.test(file.rel)) {
    if (file.isTest) return findings;
    const lines = raw.split(/\r?\n/);
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i] ?? "";
      if (!line.trim().startsWith("#") && SH_PKILL_PATTERN.test(line)) {
        SH_PKILL_PATTERN.lastIndex = 0;
        push(findings, {
          file: file.rel, line: i + 1, rule: "sh-pkill-f-pattern-kill", category: "structure", rung: "R0", severity: "error",
          message: "Killing processes by argv pattern (pkill -f / pgrep | kill) can terminate unrelated agent/dev-server worktrees.",
          fix: "Capture the exact child PID at spawn time and kill only that PID (or process group).",
        });
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
      push(findings, {
        file: file.rel, line: lineOf(raw, idx), rule: "drizzle-timestamp-missing-timezone", category: "structure", rung: "R1", severity: "warn",
        message: "Drizzle Postgres timestamp() without { withTimezone: true } stores timezone-naive timestamps and drifts across regions.",
        fix: 'Specify timestamp("col", { withTimezone: true }) for all Postgres timestamp columns.',
      });
    }
  }
  const parsed = ast ?? parseTsAst(file);
  if (!parsed) return findings;
  walkAst(parsed, (node) => {
    checkReactEffectStateSync(file, raw, node, findings);
    checkLoopSchemaCompileAndSlice(file, raw, node, findings);
  });
  return findings;
}
