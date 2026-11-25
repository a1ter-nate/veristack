import type { ScannedFile } from "../discover.ts";
import { lineOf, maskCode } from "../test-lexical.ts";
import type { Finding } from "../types.ts";

const ERR_RESPONSE_STMT =
  /^[ \t]*(?!return\b|throw\b)(?:res|reply|response)\s*\.\s*status\s*\(\s*(?:4\d{2}|5\d{2})\s*\)\s*\.\s*(?:send|json|end)\s*\([^;\n]*\)\s*;?[ \t]*$/gm;
const EXPRESS_SEND_NUMERIC = /\b(?:res|reply|response)\s*\.\s*send\s*\(\s*(?:4\d{2}|5\d{2})\s*\)/g;
const LOSSY_ZOD_COERCE = /\bz\s*\.\s*coerce\s*\.\s*(?:number|boolean)\s*\(\s*\)/g;
const NUMERIC_FIELD =
  "(?:count|remaining|version|minute|hour|port|amount|price|balance|quantity|qty|offset|retries|retryCount|score|temp|temperature|timeoutMs|delayMs|limit|threshold)";
const FALSY_NUMERIC_IF = new RegExp(`\\bif\\s*\\(\\s*!\\s*((?:[A-Za-z_$][A-Za-z0-9_$.]*\\.)?${NUMERIC_FIELD})\\b\\s*\\)`, "g");
const FALSY_NUMERIC_OR = new RegExp(
  `\\b((?:[A-Za-z_$][A-Za-z0-9_$.]*\\.)?${NUMERIC_FIELD})\\b\\s*\\|\\|\\s*(?!true\\b|false\\b)`,
  "g",
);
const FLOATING_SIDE_EFFECT =
  /^[ \t]*(?!await\b|return\b|throw\b|void\b|const\b|let\b|var\b|if\b|while\b|for\b|export\b|function\b|async\b)(?:[A-Za-z_$][A-Za-z0-9_$.]*\.)?(?:shutdown|flush|commit|writeBatch|setDoc|updateDoc|deleteDoc|invalidateCache|deleteCacheEntry)\s*\([^;\n]*\)\s*;?[ \t]*$/gm;
const UNBOUNDED_IN_QUERY = /\.\s*where\s*\([^,\n]+,\s*(?:"in"|'in'|"array-contains-any"|'array-contains-any')\s*,\s*([^)\n]+)\)/g;
const BATCH_WRITE_CALL = /\b(?:batch|writeBatch)\s*\.\s*(?:set|update|delete)\s*\(/g;
const MUTATING_ARRAY_ASSIGN =
  /\b(?:const|let|var)\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*[A-Za-z_$][A-Za-z0-9_$.]*\.\s*(?:push|unshift)\s*\(|\breturn\s+[A-Za-z_$][A-Za-z0-9_$.]*\.\s*(?:push|unshift)\s*\(/g;
const CACHE_GET_RETURN = /\breturn\s+(?:this\.)?[A-Za-z_$][A-Za-z0-9_$]*[Cc]ache\s*\.\s*get\s*\([^)\n]+\)\s*;?/g;
const ENV_AUTH_BYPASS =
  /\b(?:process\.env|os\.environ(?:\.get)?)\s*(?:\.\s*|\[\s*["']|\(\s*["'])(?:DEBUG_MODE|DEBUG_USER|SKIP_AUTH|DISABLE_AUTH|BYPASS_AUTH|MOCK_AUTH|NO_AUTH)\b/g;
const PASSTHROUGH_SCHEMA = /\.\s*(?:passthrough|catchall)\s*\(/g;
const RAW_DB_REEXPORT =
  /^\s*export\s*\{[^}]*\b(?:getFirestore|getDatabase|firestore|dbClient|prisma|pgPool)\b[^}]*\}\s*from\s*["'][^"']+["']/gm;
const API_KEY_SIGNING = /\b(?:createHmac|jwt\.sign|signJwt)\s*\([^;\n]*\b[A-Z0-9_]*API_KEY\b/g;
const UNDEFINED_IN_DB_WRITE = /\.\s*(?:set|update|add)\s*\(\s*\{[^}]{0,400}(?:\?\?\s*undefined\b|:\s*undefined\b)/g;
const NOSQL_EQ_FALSE = /\.\s*where\s*\([^,\n]+,\s*(?:"=="|'==')\s*,\s*false\s*\)/g;
const WARN_ONLY_CATCH =
  /\bcatch\s*\([^)]*\)\s*\{\s*(?:logger|log|console)\s*\.\s*(?:warn|info|debug)\s*\([^}]*\)\s*;?\s*\}/g;
const IGNORED_PARTIAL_STATUS = /\b(?:status\s*===?\s*207|multiStatus|partialFailure)\b/i;
const DO_WHILE_LOOP = /\bdo\s*\{([\s\S]{1,1200}?)\}\s*while\s*\([^)]+\)/g;

const BOOLEAN_PREFIX = /(?:^|\.)(?:is|has|can|should|allow|enable|disable|was|did|use|skip)[A-Z_]/;
const LENGTH_NAME = /(?:len|length|count|size|total|nextLen|newLen)/i;
const CHUNK_GUARD = /\b(?:chunk|chunks|slice|splice|BATCH_SIZE|MAX_IN|IN_LIMIT|batchSize|maxBatch|450|500|30)\b/;
const AUTH_PATH_OR_NAME = /(?:auth|middleware|guard|session|token|rbac|permission|security)/i;
const DB_ADAPTER_PATH = /(?:^|\/)(?:db|database|firestore|persistence|storage)\.(?:[cm]?[jt]s)$/i;
const CACHE_INVALIDATOR = /\b(?:deleteCache|invalidateCache|evictCache|clearCache)[A-Za-z0-9_]*\b|\bcache\.delete\b/;
const EXPORTED_MUTATOR = /\bexport\s+(?:async\s+)?function\s+((?:create|update|delete|remove|upsert|set|patch|save)[A-Z][A-Za-z0-9_]*)\s*\(/g;

function extractBlockAfter(text: string, startIndex: number): string {
  const open = text.indexOf("{", startIndex);
  if (open < 0) return "";
  let depth = 0;
  for (let i = open; i < text.length; i++) {
    const ch = text[i];
    if (ch === "{") depth += 1;
    else if (ch === "}") {
      depth -= 1;
      if (depth === 0) return text.slice(open, i + 1);
    }
  }
  return text.slice(open, Math.min(text.length, open + 1500));
}

function stripCommentsAndRegexes(masked: string): string {
  const out = [...masked];
  let lastNonWs = "";
  for (let i = 0; i < out.length; i++) {
    const ch = out[i] ?? "";
    const next = out[i + 1] ?? "";
    if (ch === "/" && next === "/") {
      while (i < out.length && out[i] !== "\n") {
        out[i] = " ";
        i += 1;
      }
      continue;
    }
    if (ch === "/" && next === "*") {
      out[i] = " ";
      out[i + 1] = " ";
      i += 2;
      while (i < out.length) {
        if (out[i] === "*" && out[i + 1] === "/") {
          out[i] = " ";
          out[i + 1] = " ";
          i += 1;
          break;
        }
        if (out[i] !== "\n") out[i] = " ";
        i += 1;
      }
      continue;
    }
    if (ch === "/" && (lastNonWs === "" || "=(,:!&|?;{[}\n".includes(lastNonWs))) {
      let inClass = false;
      let escaped = false;
      let end = -1;
      for (let j = i + 1; j < out.length; j++) {
        const c = out[j] ?? "";
        if (c === "\n" || c === "\r") break;
        if (escaped) {
          escaped = false;
          continue;
        }
        if (c === "\\") {
          escaped = true;
          continue;
        }
        if (c === "[") inClass = true;
        else if (c === "]") inClass = false;
        else if (c === "/" && !inClass) {
          end = j;
          break;
        }
      }
      if (end > i) {
        for (let k = i; k <= end; k++) out[k] = " ";
        i = end;
        lastNonWs = ")";
        continue;
      }
    }
    if (ch.trim()) lastNonWs = ch;
  }
  return out.join("");
}

function extractFunctionBody(text: string, startIndex: number): string {
  const openParen = text.indexOf("(", startIndex);
  if (openParen < 0) return extractBlockAfter(text, startIndex);
  let pDepth = 0;
  let afterParams = openParen;
  for (let i = openParen; i < text.length; i++) {
    const ch = text[i];
    if (ch === "(") pDepth += 1;
    else if (ch === ")") {
      pDepth -= 1;
      if (pDepth === 0) {
        afterParams = i + 1;
        break;
      }
    }
  }
  let braceDepth = 0;
  let angleDepth = 0;
  for (let i = afterParams; i < text.length; i++) {
    const ch = text[i];
    if (ch === "<") angleDepth += 1;
    else if (ch === ">" && angleDepth > 0) angleDepth -= 1;
    else if (ch === "{" && angleDepth === 0 && braceDepth === 0) {
      return extractBlockAfter(text, i);
    } else if (ch === "{") braceDepth += 1;
    else if (ch === "}" && braceDepth > 0) braceDepth -= 1;
  }
  return "";
}

function isNextNonEmptyExecutable(text: string, afterOffset: number): boolean {
  let sawSingleCloseBrace = false;
  for (const line of text.slice(afterOffset).split(/\r?\n/)) {
    const t = line.trim();
    if (!t) continue;
    if (t === "}" && !sawSingleCloseBrace) {
      sawSingleCloseBrace = true;
      continue;
    }
    if (
      t.startsWith("}") ||
      t.startsWith("else") ||
      t.startsWith("break") ||
      t.startsWith("return") ||
      t.startsWith("case ") ||
      t.startsWith("default:")
    ) {
      return false;
    }
    return true;
  }
  return false;
}

function push(
  findings: Finding[],
  file: ScannedFile,
  raw: string,
  offset: number,
  rule: string,
  rung: Finding["rung"],
  severity: Finding["severity"],
  message: string,
  fix: string,
): void {
  const line = lineOf(raw, offset);
  findings.push({ id: `RG:${rule}:${file.rel}:${line}`, rule, category: "structure", rung, severity, file: file.rel, line, message, fix });
}

export function analyzeRuntimeGuards(file: ScannedFile): Finding[] {
  const findings: Finding[] = [];
  const raw = file.content;
  const code = stripCommentsAndRegexes(maskCode(raw, file.language));

  if (file.language === "python") {
    for (const m of raw.matchAll(ENV_AUTH_BYPASS)) {
      const idx = m.index ?? 0;
      if (code[idx] === " ") continue;
      push(
        findings, file, raw, idx, "no-env-auth-bypass", "R0", "error",
        `Environment-variable auth bypass detected (${m[0].trim()}).`,
        "Remove environment-based auth short-circuits; use signed test credentials or DI auth adapters.",
      );
    }
    return findings;
  }

  if (file.language !== "typescript" && file.language !== "javascript") return findings;

  for (const m of code.matchAll(ERR_RESPONSE_STMT)) {
    const start = m.index ?? 0;
    if (!isNextNonEmptyExecutable(code, start + m[0].length)) continue;
    push(
      findings, file, raw, start, "no-fallthrough-after-error-response", "R1", "error",
      "HTTP error response (4xx/5xx) does not return or throw and falls through to subsequent handler statements.",
      "Prefix with 'return' (e.g. return res.status(400).json(...)) so the handler halts immediately on error.",
    );
  }

  for (const m of code.matchAll(EXPRESS_SEND_NUMERIC)) {
    push(
      findings, file, raw, m.index ?? 0, "express-send-numeric-status", "R1", "error",
      `Numeric HTTP status passed to res.send() (${m[0].trim()}) instead of res.status(...).send(...) or res.sendStatus(...).`,
      "Use res.status(code).json(...) or res.sendStatus(code).",
    );
  }

  for (const m of code.matchAll(LOSSY_ZOD_COERCE)) {
    push(
      findings, file, raw, m.index ?? 0, "no-lossy-schema-coerce", "R1", "warn",
      `${m[0].trim()} silently coerces null and empty string "" into 0/false at DTO boundaries.`,
      "Use z.preprocess to normalize null/empty-string to undefined before validating strict number/boolean types.",
    );
  }

  let falsyCount = 0;
  for (const re of [FALSY_NUMERIC_IF, FALSY_NUMERIC_OR]) {
    for (const m of code.matchAll(re)) {
      const ident = m[1] ?? "";
      if (BOOLEAN_PREFIX.test(ident) || ++falsyCount > 5) continue;
      push(
        findings, file, raw, m.index ?? 0, "no-falsy-check-on-number", "R1", "warn",
        `Falsy check/coalescing on numeric-named value '${ident}' rejects or overwrites valid 0.`,
        "Use explicit nullish checks (val == null / val ?? fallback) instead of !val or val || fallback.",
      );
    }
  }

  const rawLines = raw.split(/\r?\n/);
  const hasAsyncContext = /\b(?:async|await|Promise|then)\b/.test(code);
  const localSyncFns = new Set<string>();
  for (const fm of code.matchAll(/(^|[^\w$])(async\s+)?function\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*\(/g)) {
    if (!fm[2] && fm[3]) localSyncFns.add(fm[3]);
  }
  for (const m of code.matchAll(FLOATING_SIDE_EFFECT)) {
    const start = m.index ?? 0;
    const callText = m[0].trim();
    const bareMatch = /^([A-Za-z_$][A-Za-z0-9_$]*)\s*\(/.exec(callText);
    if (bareMatch && bareMatch[1] && (localSyncFns.has(bareMatch[1]) || !hasAsyncContext)) continue;
    const rawLine = rawLines[lineOf(raw, start) - 1] ?? "";
    if (/\.then\s*\(|\.catch\s*\(|\/\/\s*fire-and-forget/i.test(rawLine)) continue;
    push(
      findings, file, raw, start, "no-floating-side-effect-promise", "R1", "error",
      `Side-effect persistence/shutdown call '${callText}' is neither awaited nor explicitly tracked.`,
      "Await the async call or register it in a shutdown-drain tracker so writes and flushes cannot silently drop.",
    );
  }

  for (const m of code.matchAll(/\.\s*where\s*\(/g)) {
    const idx = m.index ?? 0;
    const rawCall = raw.slice(idx, idx + 140);
    const inMatch = UNBOUNDED_IN_QUERY.exec(rawCall);
    UNBOUNDED_IN_QUERY.lastIndex = 0;
    if (inMatch) {
      const arg = (inMatch[1] ?? "").trim();
      if (!(arg.startsWith("[") && arg.split(",").length <= 10) && !CHUNK_GUARD.test(raw.slice(Math.max(0, idx - 350), idx + 250))) {
        push(
          findings, file, raw, idx, "no-unbounded-query-disjunction", "R1", "warn",
          "Disjunction query ('in' / 'array-contains-any') passes a dynamic array without visible chunking.",
          "Chunk the input array to stay within the database's disjunction limit (e.g. <= 30 items per query).",
        );
      }
    }
    if (NOSQL_EQ_FALSE.test(rawCall)) {
      NOSQL_EQ_FALSE.lastIndex = 0;
      push(
        findings, file, raw, idx, "nosql-equality-on-optional-bool", "R2", "warn",
        'Document equality query \'.where(field, "==", false)\' silently excludes legacy records where the field is missing.',
        "Backfill required defaults or query broadly and filter tri-state values ({ missing, false, true }) explicitly.",
      );
    }
  }

  for (const m of code.matchAll(BATCH_WRITE_CALL)) {
    const idx = m.index ?? 0;
    const win = code.slice(Math.max(0, idx - 450), idx + 350);
    if (!/\b(?:for|while)\s*\(/.test(win) || CHUNK_GUARD.test(win)) continue;
    push(
      findings, file, raw, idx, "no-unbounded-batch-write", "R1", "warn",
      "Loop writes to a database batch without a visible chunk/size cap (risks exceeding 500-write batch limits).",
      "Chunk writes into bounded batches (e.g. <= 450 operations per commit).",
    );
    break;
  }

  for (const m of code.matchAll(MUTATING_ARRAY_ASSIGN)) {
    if (m[1] && LENGTH_NAME.test(m[1])) continue;
    push(
      findings, file, raw, m.index ?? 0, "no-mutating-array-return-use", "R1", "error",
      `Array mutator return value used (${m[0].trim()}) — push/unshift returns the new length, not the array.`,
      "Mutate the array on its own statement or build a new array via [...arr, item].",
    );
  }

  for (const m of code.matchAll(CACHE_GET_RETURN)) {
    const idx = m.index ?? 0;
    const win = code.slice(Math.max(0, idx - 300), idx + 200);
    if (/\b(?:structuredClone|cloneDeep|Object\.freeze)\b|:\s*(?:string|number|boolean)\s*\|\s*undefined/.test(win)) continue;
    push(
      findings, file, raw, idx, "cache-uncloned-return", "R1", "warn",
      "Returning a live value directly from an in-memory cache risks caller mutations poisoning cached state.",
      "Clone (structuredClone) or freeze cached objects before returning, or type the cache value as Readonly/primitive.",
    );
  }

  if (AUTH_PATH_OR_NAME.test(file.rel) || /\b(?:auth|verifyToken|requireRole|authenticate)\b/i.test(code)) {
    for (const m of raw.matchAll(ENV_AUTH_BYPASS)) {
      const idx = m.index ?? 0;
      if (code[idx] === " ") continue;
      push(
        findings, file, raw, idx, "no-env-auth-bypass", "R0", "error",
        `Environment-variable auth bypass detected (${m[0].trim()}).`,
        "Remove environment-based auth short-circuits; use signed test credentials or DI auth adapters.",
      );
    }
  }

  for (const m of code.matchAll(PASSTHROUGH_SCHEMA)) {
    push(
      findings, file, raw, m.index ?? 0, "no-passthrough-patch-schema", "R1", "warn",
      "Permissive schema (.passthrough() / .catchall()) allows unvalidated or dotted keys past boundary checks.",
      "Use strict schemas (.strict() or default strip) with an explicit allowlist of accepted fields.",
    );
  }

  if (!DB_ADAPTER_PATH.test(file.rel)) {
    for (const m of raw.matchAll(RAW_DB_REEXPORT)) {
      const idx = m.index ?? 0;
      if (code[idx] === " ") continue;
      push(
        findings, file, raw, idx, "no-raw-db-reexport", "R1", "warn",
        "Re-exporting a raw database SDK client lets callers bypass audited DAO/repository boundaries.",
        "Keep raw DB client access internal to the single persistence adapter module.",
      );
    }
  }

  for (const m of raw.matchAll(API_KEY_SIGNING)) {
    const idx = m.index ?? 0;
    if (code[idx] === " ") continue;
    push(
      findings, file, raw, idx, "no-api-key-as-signing-secret", "R0", "error",
      "Third-party API key reused as a cryptographic HMAC/JWT signing secret.",
      "Provision a dedicated signing secret env var independent of vendor API keys so rotation stays decoupled.",
    );
  }

  if (CACHE_INVALIDATOR.test(code)) {
    for (const m of code.matchAll(EXPORTED_MUTATOR)) {
      const start = m.index ?? 0;
      const body = extractFunctionBody(code, start);
      if (body && !CACHE_INVALIDATOR.test(body)) {
        push(
          findings, file, raw, start, "dao-write-missing-cache-invalidation", "R1", "warn",
          `Exported mutator '${m[1] ?? "mutator"}' in cache-aware module does not invalidate the cache.`,
          "Invalidate or update the relevant cache entry after committing the write.",
        );
      }
    }
  }

  for (const m of code.matchAll(UNDEFINED_IN_DB_WRITE)) {
    push(
      findings, file, raw, m.index ?? 0, "no-undefined-in-db-write", "R1", "warn",
      "Explicit undefined property passed into document .set()/.update()/.add() crashes strict document stores.",
      "Conditionally spread optional properties (...(val !== undefined ? { key: val } : {})) or strip undefined keys.",
    );
  }

  for (const m of code.matchAll(WARN_ONLY_CATCH)) {
    push(
      findings, file, raw, m.index ?? 0, "no-warn-only-error-catch", "R1", "warn",
      "Catch block only logs at warn/info/debug without rethrowing, returning a typed error, or recording error telemetry.",
      "Return a typed error result, rethrow, or log at error level with structured exception telemetry.",
    );
  }

  for (const m of code.matchAll(DO_WHILE_LOOP)) {
    if (!/\bawait\b/.test(m[1] ?? "")) continue;
    const idx = m.index ?? 0;
    const win = code.slice(Math.max(0, idx - 200), idx + (m[0]?.length ?? 0) + 120);
    if (/\b(?:maxIter|max_iter|maxAttempts|maxPages|pageCount|deadline|timeout|limit|fuel|budget|countdown)\b/i.test(win)) continue;
    push(
      findings, file, raw, idx, "unbounded-loop-risk", "R1", "warn",
      "Async do..while loop has no visible iteration or page cap (risks infinite pagination/retry hangs).",
      "Bound the loop with an explicit maxPages/maxIterations ceiling.",
    );
  }

  if (IGNORED_PARTIAL_STATUS.test(code) && !/\b(?:errors?|failed|failures|rejected)\b/i.test(code)) {
    push(
      findings, file, raw, 0, "no-ignored-partial-failure", "R1", "warn",
      "Multi-status (207) / partial-failure response referenced without inspecting per-item errors.",
      "Inspect every item status in 207 responses and surface partial failures explicitly.",
    );
  }

  for (const m of code.matchAll(/\buseEffect\s*\(\s*\(\s*\)\s*=>\s*\{/g)) {
    const start = m.index ?? 0;
    const body = extractBlockAfter(code, start);
    if (!body || !/\bawait\b/.test(body) || !/\bset[A-Z][A-Za-z0-9_]*\s*\(/.test(body)) continue;
    if (/\b(?:AbortController|signal\.aborted|controller\.abort|requestId|reqId|generation|genRef|seqRef|runId|latestRef|versionRef)\b/.test(body)) {
      continue;
    }
    push(
      findings, file, raw, start, "async-effect-stale-guard", "R3", "warn",
      "Async useEffect updates state after await without AbortController or a monotonic generation guard (stale-response race).",
      "Pass an AbortController signal to async calls or compare a monotonic request/generation counter before calling setState.",
    );
  }

  return findings;
}
