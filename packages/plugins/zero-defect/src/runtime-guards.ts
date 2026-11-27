import type { ScannedFile } from "@veristack/plugin";
import { lineOf, maskCode } from "@veristack/plugin";
import type { Finding } from "@veristack/plugin";

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

function stripCommentsAndRegexes(raw: string, language?: string): string {
  return maskCode(raw, language);
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

interface RuntimeGuardFinding {
  file: ScannedFile;
  raw: string;
  offset: number;
  rule: string;
  rung: Finding["rung"];
  severity: Finding["severity"];
  message: string;
  fix: string;
}

function push(findings: Finding[], entry: RuntimeGuardFinding): void {
  const line = lineOf(entry.raw, entry.offset);
  findings.push({
    id: `RG:${entry.rule}:${entry.file.rel}:${line}`,
    rule: entry.rule,
    category: "structure",
    rung: entry.rung,
    severity: entry.severity,
    file: entry.file.rel,
    line,
    message: entry.message,
    fix: entry.fix,
  });
}

function scanHttpAndSchemaGuards(file: ScannedFile, raw: string, code: string, findings: Finding[]): void {
  if (!code) return;
  if (!file.rel) throw new Error("ScannedFile must have rel.");
  for (const m of code.matchAll(ERR_RESPONSE_STMT)) {
    const start = m.index ?? 0;
    if (!isNextNonEmptyExecutable(code, start + m[0].length)) continue;
    push(findings, { file, raw, offset: start, rule: "no-fallthrough-after-error-response", rung: "R1", severity: "error", message: "HTTP error response (4xx/5xx) does not return or throw and falls through to subsequent handler statements.", fix: "Prefix with 'return' (e.g. return res.status(400).json(...)) so the handler halts immediately on error." });
  }
  for (const m of code.matchAll(EXPRESS_SEND_NUMERIC)) {
    push(findings, { file, raw, offset: m.index ?? 0, rule: "express-send-numeric-status", rung: "R1", severity: "error", message: `Numeric HTTP status passed to res.send() (${m[0].trim()}) instead of res.status(...).send(...) or res.sendStatus(...).`, fix: "Use res.status(code).json(...) or res.sendStatus(code)." });
  }
  for (const m of code.matchAll(LOSSY_ZOD_COERCE)) {
    push(findings, { file, raw, offset: m.index ?? 0, rule: "no-lossy-schema-coerce", rung: "R1", severity: "warn", message: `${m[0].trim()} silently coerces null and empty string "" into 0/false at DTO boundaries.`, fix: "Use z.preprocess to normalize null/empty-string to undefined before validating strict number/boolean types." });
  }
  let falsyCount = 0;
  for (const re of [FALSY_NUMERIC_IF, FALSY_NUMERIC_OR]) {
    for (const m of code.matchAll(re)) {
      const ident = m[1] ?? "";
      if (BOOLEAN_PREFIX.test(ident) || ++falsyCount > 5) continue;
      push(findings, { file, raw, offset: m.index ?? 0, rule: "no-falsy-check-on-number", rung: "R1", severity: "warn", message: `Falsy check/coalescing on numeric-named value '${ident}' rejects or overwrites valid 0.`, fix: "Use explicit nullish checks (val == null / val ?? fallback) instead of !val or val || fallback." });
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
    if (bareMatch?.[1] && (localSyncFns.has(bareMatch[1]) || !hasAsyncContext)) continue;
    const rawLine = rawLines[lineOf(raw, start) - 1] ?? "";
    if (/\.then\s*\(|\.catch\s*\(|\/\/\s*fire-and-forget/i.test(rawLine)) continue;
    push(findings, { file, raw, offset: start, rule: "no-floating-side-effect-promise", rung: "R1", severity: "error", message: `Side-effect persistence/shutdown call '${callText}' is neither awaited nor explicitly tracked.`, fix: "Await the async call or register it in a shutdown-drain tracker so writes and flushes cannot silently drop." });
  }
}

function scanDbAndCacheGuards(file: ScannedFile, raw: string, code: string, findings: Finding[]): void {
  if (!code) return;
  if (!file.rel) throw new Error("ScannedFile must have rel.");
  for (const m of code.matchAll(/\.\s*where\s*\(/g)) {
    const idx = m.index ?? 0;
    const rawCall = raw.slice(idx, idx + 140);
    const inMatch = UNBOUNDED_IN_QUERY.exec(rawCall);
    UNBOUNDED_IN_QUERY.lastIndex = 0;
    if (inMatch) {
      const arg = (inMatch[1] ?? "").trim();
      if (!(arg.startsWith("[") && arg.split(",").length <= 10) && !CHUNK_GUARD.test(raw.slice(Math.max(0, idx - 350), idx + 250))) {
        push(findings, { file, raw, offset: idx, rule: "no-unbounded-query-disjunction", rung: "R1", severity: "warn", message: "Disjunction query ('in' / 'array-contains-any') passes a dynamic array without visible chunking.", fix: "Chunk the input array to stay within the database's disjunction limit (e.g. <= 30 items per query)." });
      }
    }
    if (NOSQL_EQ_FALSE.test(rawCall)) {
      NOSQL_EQ_FALSE.lastIndex = 0;
      push(findings, { file, raw, offset: idx, rule: "nosql-equality-on-optional-bool", rung: "R2", severity: "warn", message: 'Document equality query \'.where(field, "==", false)\' silently excludes legacy records where the field is missing.', fix: "Backfill required defaults or query broadly and filter tri-state values ({ missing, false, true }) explicitly." });
    }
  }
  for (const m of code.matchAll(BATCH_WRITE_CALL)) {
    const idx = m.index ?? 0;
    const win = code.slice(Math.max(0, idx - 450), idx + 350);
    if (!/\b(?:for|while)\s*\(/.test(win) || CHUNK_GUARD.test(win)) continue;
    push(findings, { file, raw, offset: idx, rule: "no-unbounded-batch-write", rung: "R1", severity: "warn", message: "Loop writes to a database batch without a visible chunk/size cap (risks exceeding 500-write batch limits).", fix: "Chunk writes into bounded batches (e.g. <= 450 operations per commit)." });
    break;
  }
  for (const m of code.matchAll(MUTATING_ARRAY_ASSIGN)) {
    if (m[1] && LENGTH_NAME.test(m[1])) continue;
    push(findings, { file, raw, offset: m.index ?? 0, rule: "no-mutating-array-return-use", rung: "R1", severity: "error", message: `Array mutator return value used (${m[0].trim()}) — push/unshift returns the new length, not the array.`, fix: "Mutate the array on its own statement or build a new array via [...arr, item]." });
  }
  for (const m of code.matchAll(CACHE_GET_RETURN)) {
    const idx = m.index ?? 0;
    const win = code.slice(Math.max(0, idx - 300), idx + 200);
    if (/\b(?:structuredClone|cloneDeep|Object\.freeze)\b|:\s*(?:string|number|boolean)\s*\|\s*undefined/.test(win)) continue;
    push(findings, { file, raw, offset: idx, rule: "cache-uncloned-return", rung: "R1", severity: "warn", message: "Returning a live value directly from an in-memory cache risks caller mutations poisoning cached state.", fix: "Clone (structuredClone) or freeze cached objects before returning, or type the cache value as Readonly/primitive." });
  }
  for (const m of code.matchAll(UNDEFINED_IN_DB_WRITE)) {
    push(findings, { file, raw, offset: m.index ?? 0, rule: "no-undefined-in-db-write", rung: "R1", severity: "warn", message: "Explicit undefined property passed into document .set()/.update()/.add() crashes strict document stores.", fix: "Conditionally spread optional properties (...(val !== undefined ? { key: val } : {})) or strip undefined keys." });
  }
  if (CACHE_INVALIDATOR.test(code)) {
    for (const m of code.matchAll(EXPORTED_MUTATOR)) {
      const start = m.index ?? 0;
      const body = extractFunctionBody(code, start);
      if (body && !CACHE_INVALIDATOR.test(body)) {
        push(findings, { file, raw, offset: start, rule: "dao-write-missing-cache-invalidation", rung: "R1", severity: "warn", message: `Exported mutator '${m[1] ?? "mutator"}' in cache-aware module does not invalidate the cache.`, fix: "Invalidate or update the relevant cache entry after committing the write." });
      }
    }
  }
}

function scanSecurityAndAsyncGuards(file: ScannedFile, raw: string, code: string, findings: Finding[]): void {
  if (!code) return;
  if (!file.rel) throw new Error("ScannedFile must have rel.");
  if (AUTH_PATH_OR_NAME.test(file.rel) || /\b(?:auth|verifyToken|requireRole|authenticate)\b/i.test(code)) {
    for (const m of raw.matchAll(ENV_AUTH_BYPASS)) {
      const idx = m.index ?? 0;
      if (code[idx] === " ") continue;
      push(findings, { file, raw, offset: idx, rule: "no-env-auth-bypass", rung: "R0", severity: "error", message: `Environment-variable auth bypass detected (${m[0].trim()}).`, fix: "Remove environment-based auth short-circuits; use signed test credentials or DI auth adapters." });
    }
  }
  for (const m of code.matchAll(PASSTHROUGH_SCHEMA)) {
    push(findings, { file, raw, offset: m.index ?? 0, rule: "no-passthrough-patch-schema", rung: "R1", severity: "warn", message: "Permissive schema (.passthrough() / .catchall()) allows unvalidated or dotted keys past boundary checks.", fix: "Use strict schemas (.strict() or default strip) with an explicit allowlist of accepted fields." });
  }
  if (!DB_ADAPTER_PATH.test(file.rel)) {
    for (const m of raw.matchAll(RAW_DB_REEXPORT)) {
      const idx = m.index ?? 0;
      if (code[idx] === " ") continue;
      push(findings, { file, raw, offset: idx, rule: "no-raw-db-reexport", rung: "R1", severity: "warn", message: "Re-exporting a raw database SDK client lets callers bypass audited DAO/repository boundaries.", fix: "Keep raw DB client access internal to the single persistence adapter module." });
    }
  }
  for (const m of raw.matchAll(API_KEY_SIGNING)) {
    const idx = m.index ?? 0;
    if (code[idx] === " ") continue;
    push(findings, { file, raw, offset: idx, rule: "no-api-key-as-signing-secret", rung: "R0", severity: "error", message: "Third-party API key reused as a cryptographic HMAC/JWT signing secret.", fix: "Provision a dedicated signing secret env var independent of vendor API keys so rotation stays decoupled." });
  }
  for (const m of code.matchAll(WARN_ONLY_CATCH)) {
    push(findings, { file, raw, offset: m.index ?? 0, rule: "no-warn-only-error-catch", rung: "R1", severity: "warn", message: "Catch block only logs at warn/info/debug without rethrowing, returning a typed error, or recording error telemetry.", fix: "Return a typed error result, rethrow, or log at error level with structured exception telemetry." });
  }
  for (const m of code.matchAll(DO_WHILE_LOOP)) {
    if (!/\bawait\b/.test(m[1] ?? "")) continue;
    const idx = m.index ?? 0;
    const win = code.slice(Math.max(0, idx - 200), idx + (m[0]?.length ?? 0) + 120);
    if (/\b(?:maxIter|max_iter|maxAttempts|maxPages|pageCount|deadline|timeout|limit|fuel|budget|countdown)\b/i.test(win)) continue;
    push(findings, { file, raw, offset: idx, rule: "unbounded-loop-risk", rung: "R1", severity: "warn", message: "Async do..while loop has no visible iteration or page cap (risks infinite pagination/retry hangs).", fix: "Bound the loop with an explicit maxPages/maxIterations ceiling." });
  }
  if (IGNORED_PARTIAL_STATUS.test(code) && !/\b(?:errors?|failed|failures|rejected)\b/i.test(code)) {
    push(findings, { file, raw, offset: 0, rule: "no-ignored-partial-failure", rung: "R1", severity: "warn", message: "Multi-status (207) / partial-failure response referenced without inspecting per-item errors.", fix: "Inspect every item status in 207 responses and surface partial failures explicitly." });
  }
  for (const m of code.matchAll(/\buseEffect\s*\(\s*\(\s*\)\s*=>\s*\{/g)) {
    const start = m.index ?? 0;
    const body = extractBlockAfter(code, start);
    if (!body || !/\bawait\b/.test(body) || !/\bset[A-Z][A-Za-z0-9_]*\s*\(/.test(body)) continue;
    if (/\b(?:AbortController|signal\.aborted|controller\.abort|requestId|reqId|generation|genRef|seqRef|runId|latestRef|versionRef)\b/.test(body)) continue;
    const flagMatch = /\blet\s+(cancelled|canceled|ignore|ignored|active|mounted|isCurrent|disposed)\s*=\s*(false|true)\b/.exec(body);
    if (flagMatch?.[1] && flagMatch[2]) {
      const fName = flagMatch[1];
      const flipVal = flagMatch[2] === "false" ? "true" : "false";
      const cleanupIdx = body.search(/\breturn\s*\(\s*\)\s*=>/);
      const cleanupTail = cleanupIdx >= 0 ? body.slice(cleanupIdx) : "";
      const beforeCleanup = body.slice(0, cleanupIdx >= 0 ? cleanupIdx : body.length);
      const hasFlip = cleanupTail.replace(/\s+/g, "").includes(`${fName}=${flipVal}`);
      const hasGuard = beforeCleanup.replace(/\s+/g, "").includes(`!${fName}`) || beforeCleanup.replace(/\s+/g, "").includes(`if(${fName})`);
      if (hasFlip && hasGuard) continue;
    }
    push(findings, { file, raw, offset: start, rule: "async-effect-stale-guard", rung: "R3", severity: "warn", message: "Async useEffect updates state after await without AbortController or a monotonic generation guard (stale-response race).", fix: "Pass an AbortController signal to async calls or compare a monotonic request/generation counter before calling setState." });
  }
}

export function analyzeRuntimeGuards(file: ScannedFile): Finding[] {
  const findings: Finding[] = [];
  const raw = file.content;
  const code = stripCommentsAndRegexes(maskCode(raw, file.language));
  if (file.language === "python") {
    for (const m of raw.matchAll(ENV_AUTH_BYPASS)) {
      const idx = m.index ?? 0;
      if (code[idx] === " ") continue;
      push(findings, { file, raw, offset: idx, rule: "no-env-auth-bypass", rung: "R0", severity: "error", message: `Environment-variable auth bypass detected (${m[0].trim()}).`, fix: "Remove environment-based auth short-circuits; use signed test credentials or DI auth adapters." });
    }
    return findings;
  }
  if (file.language !== "typescript" && file.language !== "javascript") return findings;
  scanHttpAndSchemaGuards(file, raw, code, findings);
  scanDbAndCacheGuards(file, raw, code, findings);
  scanSecurityAndAsyncGuards(file, raw, code, findings);
  return findings;
}
