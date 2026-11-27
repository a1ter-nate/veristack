import { scanLexical } from "../anti-slop/lexical-mask.ts";
import type { ScannedFile } from "../discover.ts";
import { lineOf, maskCode } from "../test-lexical.ts";
import type { Finding } from "../types.ts";

const UNESCAPED_SCRIPT_INTERP =
  /\baddInitScript\s*\(\s*`[^`]*\$\{(?![^}]*JSON\.stringify)[^}]+\}|<script\b[^>]*>[^<\n]*\$\{(?![^}]*JSON\.stringify)[^}]+\}/g;
const PROTO_NULL_LITERAL = /\{\s*__proto__\s*:\s*null\b/g;
const IDENTITY_REPLACE =
  /\.\s*replace(?:All)?\s*\(\s*(?:"([^"\\]{1,40})"|'([^'\\]{1,40})'|\/([^/\\[\]()+*?.^$|]{1,40})\/g?)\s*,\s*(?:"([^"\\]{1,40})"|'([^'\\]{1,40})')\s*\)/g;
const UNESCAPED_REGEXP_TEMPLATE = /\bnew\s+RegExp\s*\(\s*`[^`]*\$\{(?![^}]*(?:[Ee]scape|[A-Z][A-Z0-9_]+))[^}]+\}/g;
const EMPTY_ALT_INSIDE = /(?<!\\)(?:\(\?:\||\([|]|\|\)|\|\|)/;
const ORM_UNFILTERED_BULK = /\.\s*(?:deleteMany|deleteAll)\s*\(\s*(?:\{\s*\}\s*)?\)|\.\s*updateMany\s*\(\s*\{\s*data\s*:/g;
const NONCANONICAL_MIME_KEY = /\bcontent\s*:\s*\{\s*["'](?:[A-Z][^"']*\/[^"']*|[^"']+;[^"']*|\s+[^"']+|[^"']+\s+)["']\s*:/g;
const PY_CASE_SENSITIVE_HEADER =
  /["'](?:no-store|no-cache|chunked|gzip|keep-alive|multipart\/form-data)["']\s+in\s+([A-Za-z_][A-Za-z0-9_.]*(?:\(\))?)/g;
const TS_CASE_SENSITIVE_HEADER =
  /\b(?:header|headers|cacheControl|cache_control|contentType|content_type)\s*\.\s*includes\s*\(\s*["'](?:no-store|no-cache|chunked|gzip|keep-alive)["']\s*\)/g;
const TEARDOWN_SEQ_AWAIT =
  /\bawait\s+[A-Za-z0-9_$.]+\.(?:export|flush|save)[A-Za-z0-9_]*\s*\([^;\n]*\)\s*;\s*\r?\n[ \t]*await\s+[A-Za-z0-9_$.]+\.(?:close|dispose|destroy)\s*\(/g;
const FLOOR_CEILING_INVERSION =
  /\bMath\.(?:min|Min)\s*\([^,\n]+,\s*[A-Za-z0-9_$.]*(?:min|Min|floor|Floor)[A-Za-z0-9_]*\s*\)|\bMath\.(?:max|Max)\s*\([^,\n]+,\s*[A-Za-z0-9_$.]*(?:max|Max|cap|Cap|ceiling|Ceiling)[A-Za-z0-9_]*\s*\)/g;

const PY_EAGER_ASYNCIO = /\basyncio\.(?:Lock|Event|Semaphore|BoundedSemaphore|Condition|Queue)\s*\(/g;
const PY_ORM_DYNAMIC_KWARG = /\.\s*(?:annotate|aggregate|alias|extra)\s*\(\s*\*\*[A-Za-z_][A-Za-z0-9_.]*/g;
const PY_MKSTEMP_CALL = /\b(?:tempfile\.)?mkstemp\s*\(/g;
const PY_EXCEPT_EXCEPTION = /\bexcept\s+Exception(?:\s+as\s+[A-Za-z_][A-Za-z0-9_]*)?\s*:/g;

const RUST_SELECT_NON_CANCEL =
  /\b(?:tokio::)?select!\s*\{[\s\S]{0,1200}?\.\s*(?:read_exact|read_to_end|read_to_string|write_all|send_all)\s*\(/g;
const RUST_INSTANT_ARITH =
  /\bInstant::now\s*\(\s*\)\s*[+-]\s*[A-Za-z0-9_.:]+|\.\s*duration_since\s*\([^)\n]+\)\s*\.\s*unwrap\s*\(\s*\)/g;
const RUST_POLL_FN = /\bfn\s+poll(?:_next|_read|_write)?\s*\([^)]*\)[^{]*\{/g;
const RUST_HASHMAP_ENVS = /\.\s*envs\s*\(\s*&?\s*[A-Za-z0-9_.]*hash_?map[A-Za-z0-9_]*\s*\)/gi;

const CS_UNORDERED_SKIP = /\.\s*Skip\s*\(\s*[^)\n]+\)/g;
const CS_EF_CONTEXT =
  /\b(?:Microsoft\.EntityFrameworkCore|DbContext|DbSet|IQueryable|AsNoTracking|ToListAsync|FirstOrDefaultAsync|SingleOrDefaultAsync)\b/;

function isSymmetricBoundMath(callText: string): boolean {
  const open = callText.indexOf("(");
  const comma = callText.indexOf(",", open + 1);
  if (open < 0 || comma < 0) return false;
  const firstArg = callText.slice(open + 1, comma).trim();
  const secondArg = callText.slice(comma + 1, callText.lastIndexOf(")")).trim();
  if (/^-?\d+(?:\.\d+)?$/.test(firstArg)) return true;
  const isMin = /\bMath\.(?:min|Min)\b/.test(callText.slice(0, open));
  if (isMin) return /(?:min|Min|floor|Floor)/.test(firstArg);
  return /(?:max|Max|cap|Cap|ceiling|Ceiling)/.test(firstArg) || (/^(?:max|Max)[A-Z]/.test(secondArg) && !/(?:req|requested|val|value|input|limit|budget)/i.test(firstArg));
}
const CS_UNDISPOSED_NEW =
  /^[ \t]*(?!using\b|await\s+using\b|return\b)(?:var|[A-Za-z0-9_.<>]+)\s+[A-Za-z_][A-Za-z0-9_]*\s*=\s*new\s+(?:SqlConnection|NpgsqlConnection|FileStream|StreamReader|StreamWriter|DbCommand|SqlCommand)\s*\(/gm;
const GO_HTTP_CALL = /\b(?:http\.(?:Get|Post|PostForm|Head)|(?:http\.DefaultClient|[A-Za-z_][A-Za-z0-9_.]*(?:[Cc]lient|hc|http\w*))\.Do)\s*\(/g;

interface OssFindingInput {
  file: string;
  line: number;
  rule: string;
  rung: Finding["rung"];
  severity: Finding["severity"];
  message: string;
  fix: string;
}

function push(findings: Finding[], entry: OssFindingInput): void {
  findings.push({ id: `OSS:${entry.rule}:${entry.file}:${entry.line}`, category: "structure", ...entry });
}

function extractBlock(text: string, braceIdx: number): string {
  if (braceIdx < 0 || text[braceIdx] !== "{") return "";
  let depth = 0;
  for (let i = braceIdx; i < text.length; i++) {
    if (text[i] === "{") depth += 1;
    else if (text[i] === "}") {
      depth -= 1;
      if (depth === 0) return text.slice(braceIdx, i + 1);
    }
  }
  return text.slice(braceIdx, Math.min(text.length, braceIdx + 1500));
}

function findEnclosingPythonDef(lines: readonly string[], lineIdx: number): { isAsync: boolean } | null {
  const curLine = lines[lineIdx] ?? "";
  const curIndent = (curLine.match(/^[ \t]*/) ?? [""])[0].length;
  for (let i = lineIdx - 1; i >= 0; i--) {
    const l = lines[i] ?? "";
    const trimmed = l.trim();
    if (!trimmed || trimmed.startsWith("#")) continue;
    const indent = (l.match(/^[ \t]*/) ?? [""])[0].length;
    if (indent < curIndent) {
      const dm = /^(async\s+)?def\s+[A-Za-z_][A-Za-z0-9_]*\s*\(/.exec(trimmed);
      if (dm) return { isAsync: Boolean(dm[1]) };
      if (/^class\s+/.test(trimmed)) return null;
    }
  }
  return null;
}

function extractBalancedParenArgs(text: string, openIdx: number): string | null {
  if (text[openIdx] !== "(") return null;
  let depth = 0; let q = "";
  for (let i = openIdx; i < text.length && i < openIdx + 400; i++) {
    const ch = text[i] ?? "";
    if (q) { if (ch === "\\") { i += 1; continue; } if (ch === q) q = ""; continue; }
    if (ch === '"' || ch === "'") { q = ch; continue; }
    if (ch === "(") depth += 1;
    else if (ch === ")" && --depth === 0) return text.slice(openIdx + 1, i);
  }
  return null;
}

function scanPythonOss(file: ScannedFile, raw: string, masked: string, findings: Finding[]): void {
  if (!raw) return;
  if (!file.rel) throw new Error("ScannedFile must have rel.");
  const lines = raw.split(/\r?\n/);
  for (const m of masked.matchAll(PY_EAGER_ASYNCIO)) {
    const lineNo = lineOf(raw, m.index ?? 0);
    const enc = findEnclosingPythonDef(lines, lineNo - 1);
    if (!enc || !enc.isAsync) {
      push(findings, { file: file.rel, line: lineNo, rule: "py-no-eager-asyncio-primitive-init", rung: "R1", severity: "error", message: `Eager ${m[0].trim()}) outside an async def binds to the wrong or missing event loop.`, fix: "Lazily instantiate asyncio primitives inside an async def or pass the active loop explicitly." });
    }
  }
  for (const m of masked.matchAll(/\bopen\s*\(/g)) {
    const idx = m.index ?? 0; const line = lineOf(raw, idx);
    const openIdx = raw.indexOf("(", idx);
    const args = openIdx >= 0 ? extractBalancedParenArgs(raw, openIdx) : null;
    if (args === null || /\bencoding\s*=/.test(args) || /["'][rwxat+]*b[rwxat+]*["']/.test(args) || /^\s*def\s+open\b|\.\s*open\s*\(/.test(lines[line - 1] ?? "")) continue;
    push(findings, { file: file.rel, line, rule: "py-open-missing-encoding", rung: "R1", severity: "warn", message: "Text-mode open() without explicit encoding= depends on OS locale and fails on Windows/UTF-8 files.", fix: 'Pass encoding="utf-8" (or open in binary mode "rb"/"wb") explicitly.' });
  }
  for (const m of masked.matchAll(PY_ORM_DYNAMIC_KWARG)) {
    push(findings, { file: file.rel, line: lineOf(raw, m.index ?? 0), rule: "py-orm-dynamic-kwarg-alias-injection", rung: "R0", severity: "error", message: `Dynamic **kwargs unpacked into ORM query method (${m[0].trim()}) risks SQL alias injection.`, fix: "Allowlist explicit static alias names instead of unpacking dynamic dictionaries into ORM query methods." });
  }
  for (const m of masked.matchAll(PY_MKSTEMP_CALL)) {
    const idx = m.index ?? 0;
    if (/\b(?:finally\s*:|with\s+os\.fdopen|os\.close\s*\()/.test(masked.slice(Math.max(0, idx - 120), idx + 320))) continue;
    push(findings, { file: file.rel, line: lineOf(raw, idx), rule: "py-unscoped-fd-or-connection-lifecycle", rung: "R1", severity: "warn", message: "mkstemp() acquires an OS file descriptor without visible try/finally or with os.fdopen cleanup.", fix: "Wrap the returned fd in 'with os.fdopen(fd, ...)' or close it in a finally block." });
  }
  for (const m of masked.matchAll(PY_EXCEPT_EXCEPTION)) {
    const idx = m.index ?? 0; const block = masked.slice(idx, idx + 360);
    if (!/\.(?:close|unlink|rmtree)\s*\(/.test(block) || /\bfinally\s*:/.test(block)) continue;
    push(findings, { file: file.rel, line: lineOf(raw, idx), rule: "py-cleanup-require-finally-or-baseexception", rung: "R1", severity: "warn", message: "Resource cleanup inside 'except Exception:' is bypassed by BaseException (CancelledError, KeyboardInterrupt, pytest.skip).", fix: "Move resource cleanup into a finally: block or context manager (__exit__)." });
  }
  for (const m of raw.matchAll(PY_CASE_SENSITIVE_HEADER)) {
    const idx = m.index ?? 0; const rhs = (m[1] ?? "").trim();
    if (rhs.includes(".lower")) continue;
    const lineStart = raw.lastIndexOf("\n", idx) + 1;
    const prior = raw.slice(Math.max(0, lineStart - 160), lineStart);
    if ((rhs && /^[A-Za-z_]\w*$/.test(rhs) && prior.includes(`${rhs} =`) && prior.includes(".lower()")) || /^\s*#/.test(raw.slice(lineStart, idx)) || masked[idx + (m[0]?.indexOf(" in ") ?? 0) + 1] === " ") continue;
    push(findings, { file: file.rel, line: lineOf(raw, idx), rule: "http-case-sensitive-header-directive", rung: "R1", severity: "warn", message: "HTTP header directive check is case-sensitive without normalizing via .lower()/.toLowerCase().", fix: "Normalize HTTP header values to lowercase before matching directives." });
  }
}

function scanRustOss(file: ScannedFile, raw: string, _masked: string, findings: Finding[]): void {
  if (!raw) return;
  if (!file.rel) throw new Error("ScannedFile must have rel.");
  const prodMasked = maskCode(raw, "rust", true);
  for (const m of prodMasked.matchAll(/\b(?:struct|enum)\s+[A-Za-z_][A-Za-z0-9_]*\b/g)) {
    const declIdx = m.index ?? 0;
    const headerSlice = prodMasked.slice(Math.max(0, declIdx - 420), declIdx);
    const lastSep = Math.max(headerSlice.lastIndexOf("}"), headerSlice.lastIndexOf(";"));
    const attrs = lastSep >= 0 ? headerSlice.slice(lastSep + 1) : headerSlice;
    const denyOffsetInAttrs = attrs.search(/#\[serde\([^\]]*deny_unknown_fields[^\]]*\)\]/);
    if (denyOffsetInAttrs < 0) continue;
    const openBrace = prodMasked.indexOf("{", declIdx + m[0].length);
    const semiBefore = prodMasked.indexOf(";", declIdx + m[0].length);
    if (openBrace < 0 || (semiBefore >= 0 && semiBefore < openBrace)) continue;
    if (!/#\[serde\([^\]]*flatten[^\]]*\)\]/.test(extractBlock(prodMasked, openBrace))) continue;
    push(findings, { file: file.rel, line: lineOf(raw, Math.max(0, declIdx - attrs.length + denyOffsetInAttrs)), rule: "serde-deny-unknown-with-flatten", rung: "R0", severity: "error", message: "Combining #[serde(deny_unknown_fields)] with #[serde(flatten)] on the same struct/enum is unsupported in Serde and rejects valid payloads at runtime.", fix: "Remove deny_unknown_fields when using flatten or replace flatten with an explicit wrapper/custom Deserialize." });
  }
  for (const m of prodMasked.matchAll(RUST_SELECT_NON_CANCEL)) {
    const matchText = m[0]; const lastArrow = matchText.lastIndexOf("=>");
    const lastEq = matchText.lastIndexOf("=", lastArrow >= 0 ? lastArrow - 1 : matchText.length);
    if (lastArrow >= 0 && lastArrow > lastEq && /\.\s*(?:read_exact|read_to_end|read_to_string|write_all|send_all)\s*\(/.test(matchText.slice(lastArrow + 2))) continue;
    push(findings, { file: file.rel, line: lineOf(raw, m.index ?? 0), rule: "rust-select-non-cancel-safe", rung: "R1", severity: "error", message: "Non-cancel-safe async I/O method called inside select! arm — cancelling mid-operation drops buffered data or corrupts framing.", fix: "Use cancel-safe primitives (e.g. AsyncReadExt::read with an external buffer or framed streams) inside select!." });
  }
  for (const m of prodMasked.matchAll(RUST_INSTANT_ARITH)) {
    const idx = m.index ?? 0;
    if (/\bInstant::now\s*\(\s*\)\s*\+\s*(?:Duration::from_(?:secs|millis|micros|nanos)\s*\(\s*\d[\d_]*\s*\)|[A-Z][A-Z0-9_]{2,}\b)/.test(prodMasked.slice(idx, idx + 80))) continue;
    push(findings, { file: file.rel, line: lineOf(raw, idx), rule: "rust-unchecked-duration-or-size-arith", rung: "R1", severity: "warn", message: `Unchecked time arithmetic (${m[0].trim()}) can panic on Duration::MAX overflow or backward clock jumps.`, fix: "Use checked_add/saturating_duration_since instead of bare +/- or .unwrap() on time deltas." });
  }
  for (const m of prodMasked.matchAll(RUST_POLL_FN)) {
    const start = m.index ?? 0;
    const body = extractBlock(prodMasked, start + m[0].length - 1);
    if (!body || !/\bPoll::Pending\b/.test(body) || /\b(?:cx|waker|Context)\b/.test(body.slice(1))) continue;
    push(findings, { file: file.rel, line: lineOf(raw, start), rule: "rust-poll-pending-no-waker", rung: "R1", severity: "error", message: "Manual poll*() returns Poll::Pending without polling a child future with cx or registering cx.waker(), causing permanent hangs.", fix: "Ensure every Poll::Pending path registers a waker via cx.waker() or delegates to a sub-future polled with cx." });
  }
  for (const m of prodMasked.matchAll(/\blet\s+(?:mut\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*[^;\n]+\.(?:lock|write)\s*\(\s*\)/g)) {
    const guardName = m[1] ?? ""; const idx = m.index ?? 0;
    const rawAfter = prodMasked.slice(idx + m[0].length, idx + m[0].length + 280);
    let scopeEnd = rawAfter.length; let bDepth = 0;
    for (let k = 0; k < rawAfter.length; k++) { if (rawAfter[k] === "{") bDepth += 1; else if (rawAfter[k] === "}" && --bDepth < 0) { scopeEnd = k; break; } }
    const after = rawAfter.slice(0, scopeEnd);
    const dropMatch = /\bdrop\s*\(\s*([A-Za-z_][A-Za-z0-9_.]*)\s*\)/.exec(after);
    if (!dropMatch || dropMatch[1] === guardName) continue;
    const dropGuardIdx = after.indexOf(`drop(${guardName})`);
    if (dropGuardIdx >= 0 && dropGuardIdx < (dropMatch.index ?? 0)) continue;
    push(findings, { file: file.rel, line: lineOf(raw, idx + m[0].length + (dropMatch.index ?? 0)), rule: "rust-drop-under-lock-guard", rung: "R1", severity: "warn", message: `Dropping '${dropMatch[1]}' while lock guard '${guardName}' is still held risks re-entrant deadlocks if Drop re-acquires the lock.`, fix: `Drop '${guardName}' (or move '${dropMatch[1]}' out of the lock scope) before dropping callbacks/handles/wakers.` });
  }
  for (const m of prodMasked.matchAll(RUST_HASHMAP_ENVS)) {
    push(findings, { file: file.rel, line: lineOf(raw, m.index ?? 0), rule: "rust-hashmap-deterministic-order", rung: "R1", severity: "warn", message: "Passing a HashMap into Command::envs produces non-deterministic iteration order across runs.", fix: "Use BTreeMap for deterministic ordering when emitting env vars, CLI args, or serialized snapshots." });
  }
}

function scanCsharpOss(file: ScannedFile, raw: string, masked: string, findings: Finding[]): void {
  if (CS_EF_CONTEXT.test(masked)) {
    for (const m of masked.matchAll(CS_UNORDERED_SKIP)) {
      const idx = m.index ?? 0;
      const rawBefore = masked.slice(Math.max(0, idx - 220), idx);
      const stmtStart = Math.max(rawBefore.lastIndexOf(";"), rawBefore.lastIndexOf("{"), rawBefore.lastIndexOf("}"));
      const winBefore = stmtStart >= 0 ? rawBefore.slice(stmtStart + 1) : rawBefore;
      const winAfter = masked.slice(idx, idx + 120).split(/[;{}]/)[0] ?? "";
      if (/\.\s*OrderBy(?:Descending)?\s*\(/.test(winBefore)) continue;
      if (!/(?:_db|db|ctx|context|Set\s*<|AsNoTracking|IQueryable|Include\s*\(|ToListAsync|FirstOrDefaultAsync|SingleOrDefaultAsync)/i.test(`${winBefore}${winAfter}`)) continue;
      push(findings, { file: file.rel, line: lineOf(raw, idx), rule: "efcore-unordered-skip-or-assert", rung: "R1", severity: "warn", message: ".Skip() called without a preceding .OrderBy() produces non-deterministic query pagination across DB engines.", fix: "Chain a deterministic .OrderBy(...) (with a unique tie-breaker) before .Skip()/.Take()." });
    }
  }
  for (const m of masked.matchAll(CS_UNDISPOSED_NEW)) {
    const idx = m.index ?? 0;
    if (/\.\s*Dispose(?:Async)?\s*\(/.test(masked.slice(idx, idx + 320))) continue;
    push(findings, { file: file.rel, line: lineOf(raw, idx), rule: "csharp-undisposed-local-idisp", rung: "R1", severity: "warn", message: "Local IDisposable resource constructed without 'using' risks connection/file-handle leaks.", fix: "Declare with 'using var' or 'await using var' so disposal runs deterministically even on exceptions." });
  }
  for (const m of masked.matchAll(FLOOR_CEILING_INVERSION)) {
    if (isSymmetricBoundMath(m[0])) continue;
    push(findings, { file: file.rel, line: lineOf(raw, m.index ?? 0), rule: "math-floor-ceiling-inversion", rung: "R1", severity: "warn", message: `Possible floor/ceiling clamp inversion (${m[0].trim()}).`, fix: "Verify Math.Max is used for lower bounds (floors) and Math.Min is used for upper bounds (ceilings)." });
  }
}

function scanGoOss(file: ScannedFile, raw: string, masked: string, findings: Finding[]): void {
  const importsNetHttp = /"net\/http"/.test(raw);
  for (const m of masked.matchAll(GO_HTTP_CALL)) {
    const idx = m.index ?? 0; const tail = masked.slice(idx, idx + 500);
    if ((/\.Do\s*\(/.test(m[0]) && !importsNetHttp) || /\.Do\s*\(\s*func\b/i.test(tail) || /\bonce\.Do\s*\(/i.test(m[0])) continue;
    const openIdx = masked.indexOf("(", idx);
    const args = openIdx >= 0 ? extractBalancedParenArgs(masked, openIdx) : null;
    if (/\.Do\s*\(/.test(m[0]) && args !== null && args.includes(",")) continue;
    const lineStart = raw.lastIndexOf("\n", idx) + 1;
    const linePrefix = masked.slice(lineStart, idx);
    if (/^\s*return\b/.test(linePrefix) || /\.Body\.Close\s*\(/.test(tail)) continue;
    const varMatch = /\b([A-Za-z_]\w*)\s*,\s*[A-Za-z_]\w*\s*:?=\s*$/.exec(linePrefix);
    if (varMatch?.[1] && (tail.includes(`return ${varMatch[1]},`) || tail.includes(`return ${varMatch[1]} `) || tail.includes(`return ${varMatch[1]}\n`))) continue;
    push(findings, { file: file.rel, line: lineOf(raw, idx), rule: "go-unclosed-http-body", rung: "R1", severity: "error", message: "HTTP client call does not close resp.Body, leaking sockets and exhausting keep-alive pools.", fix: "Add 'defer resp.Body.Close()' immediately after checking err == nil." });
  }
}

function scanTsJsOssSecurity(file: ScannedFile, raw: string, masked: string, findings: Finding[]): void {
  if (!raw) return;
  if (!file.rel) throw new Error("ScannedFile must have rel.");
  for (const m of raw.matchAll(UNESCAPED_SCRIPT_INTERP)) {
    const idx = m.index ?? 0;
    if (masked[idx] === " ") continue;
    push(findings, { file: file.rel, line: lineOf(raw, idx), rule: "no-unescaped-script-interpolation", rung: "R0", severity: "error", message: "Raw template interpolation into init script or <script> tag breaks on quotes, </script>, or injection payloads.", fix: "Serialize interpolated values with JSON.stringify (escaping '</script>') or pass structured arguments." });
  }
  for (const m of masked.matchAll(PROTO_NULL_LITERAL)) {
    push(findings, { file: file.rel, line: lineOf(raw, m.index ?? 0), rule: "no-proto-null-literal", rung: "R1", severity: "warn", message: "Object literal '{ __proto__: null }' triggers slow-path/serializer quirks compared to Object.create(null) or Map.", fix: "Use Object.create(null) or a Map for prototype-free dictionaries." });
  }
  for (const m of masked.matchAll(/\.\s*replace(?:All)?\s*\(/g)) {
    const idx = m.index ?? 0;
    const idm = IDENTITY_REPLACE.exec(raw.slice(idx, idx + 120));
    IDENTITY_REPLACE.lastIndex = 0;
    if (!idm) continue;
    const search = idm[1] ?? idm[2] ?? idm[3]; const repl = idm[4] ?? idm[5];
    if (search !== undefined && repl !== undefined && search === repl) {
      push(findings, { file: file.rel, line: lineOf(raw, idx), rule: "no-identity-string-replace", rung: "R1", severity: "error", message: `Identity string replace (${idm[0].trim()}) is a no-op bug.`, fix: "Fix the intended target/replacement literal or remove the dead replace() call." });
    }
  }
  const literalConstNames = new Set<string>();
  for (const cm of raw.matchAll(/\bconst\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*(?:"[^"\n]*"|'[^'\n]*')/g)) { if (cm[1]) literalConstNames.add(cm[1]); }
  for (const m of masked.matchAll(/\bnew\s+RegExp\s*\(/g)) {
    const idx = m.index ?? 0; const rawSlice = raw.slice(idx, idx + 180);
    if (/\\\$&|escapeRegExp|RegExp\.escape/.test(raw.slice(Math.max(0, idx - 320), idx)) || !UNESCAPED_REGEXP_TEMPLATE.test(rawSlice)) continue;
    UNESCAPED_REGEXP_TEMPLATE.lastIndex = 0;
    const tmplStart = rawSlice.indexOf("`"); const tmplEnd = tmplStart >= 0 ? rawSlice.indexOf("`", tmplStart + 1) : -1;
    if (tmplStart >= 0 && tmplEnd > tmplStart) {
      const exprs = [...rawSlice.slice(tmplStart + 1, tmplEnd).matchAll(/\$\{\s*([^}]+?)\s*\}/g)].map((x) => x[1] ?? "");
      if (exprs.length > 0 && exprs.every((e) => /^[A-Za-z_$][A-Za-z0-9_$]*$/.test(e) && literalConstNames.has(e))) continue;
    }
    push(findings, { file: file.rel, line: lineOf(raw, idx), rule: "regex-empty-alternation-or-unescaped", rung: "R1", severity: "warn", message: "Unescaped template interpolation inside new RegExp(`...${...}`) risks ReDoS or metacharacter injection.", fix: "Escape dynamic segments with RegExp.escape / an explicit regex-escape helper before compiling." });
  }
  for (const sp of scanLexical(raw, true, file.language).regexSpans) {
    if (!EMPTY_ALT_INSIDE.test(raw.slice(sp.start + 1, sp.end))) continue;
    push(findings, { file: file.rel, line: lineOf(raw, sp.start), rule: "regex-empty-alternation-or-unescaped", rung: "R1", severity: "warn", message: "Regex contains an empty alternation branch (|| or (?:| / |)), silently matching empty strings or causing backtracking.", fix: "Replace empty alternation branches with an explicit optional '?' quantifier." });
  }
}

function scanTsJsOssCorrectness(file: ScannedFile, raw: string, masked: string, findings: Finding[]): void {
  if (!raw) return;
  if (!file.rel) throw new Error("ScannedFile must have rel.");
  for (const m of masked.matchAll(ORM_UNFILTERED_BULK)) {
    const idx = m.index ?? 0;
    if (/updateMany/.test(m[0]) && /\bwhere\s*:/.test(masked.slice(idx, idx + 220))) continue;
    push(findings, { file: file.rel, line: lineOf(raw, idx), rule: "orm-unfiltered-bulk-mutation", rung: "R0", severity: "error", message: `Unfiltered ORM bulk mutation (${m[0].trim()}) affects every row in the table.`, fix: "Pass an explicit scoped 'where:' filter (or require an explicit admin-confirmed truncate helper)." });
  }
  for (const m of masked.matchAll(/\bcontent\s*:\s*\{/g)) {
    const idx = m.index ?? 0;
    if (!NONCANONICAL_MIME_KEY.test(raw.slice(idx, idx + 120))) continue;
    NONCANONICAL_MIME_KEY.lastIndex = 0;
    push(findings, { file: file.rel, line: lineOf(raw, idx), rule: "schema-noncanonical-content-key", rung: "R1", severity: "warn", message: "Non-canonical MIME key (uppercase, whitespace, or charset param) in route schema content map silently skips validation.", fix: 'Use canonical lowercase MIME keys without parameters (e.g. "application/json").' });
  }
  if (/\bsetHeader\s*\(\s*["']content-length["']/i.test(raw) && /\bsetHeader\s*\(\s*["']transfer-encoding["']/i.test(raw) && !/\bremoveHeader\s*\(\s*["'](?:content-length|transfer-encoding)["']/i.test(raw)) {
    const idx = raw.search(/\bsetHeader\s*\(\s*["'](?:content-length|transfer-encoding)["']/i);
    if (masked[Math.max(0, idx)] !== " ") {
      push(findings, { file: file.rel, line: lineOf(raw, Math.max(0, idx)), rule: "http-conflicting-framing-headers", rung: "R0", severity: "error", message: "Module sets both Content-Length and Transfer-Encoding without removing the conflicting framing header (HTTP smuggling risk).", fix: "Remove Transfer-Encoding before setting Content-Length (or vice versa) and strip both on 204/304 responses." });
    }
  }
  for (const m of masked.matchAll(TEARDOWN_SEQ_AWAIT)) {
    const idx = m.index ?? 0;
    if (/\btry\s*\{/.test(masked.slice(Math.max(0, idx - 120), idx))) continue;
    push(findings, { file: file.rel, line: lineOf(raw, idx), rule: "require-try-finally-around-teardown", rung: "R1", severity: "warn", message: "Sequential flush/export before close/dispose lacks try...finally — an export error skips close() and leaks resources.", fix: "Wrap export/flush in try { ... } finally { await close(); } so teardown always executes." });
  }
  for (const m of masked.matchAll(FLOOR_CEILING_INVERSION)) {
    if (isSymmetricBoundMath(m[0])) continue;
    push(findings, { file: file.rel, line: lineOf(raw, m.index ?? 0), rule: "math-floor-ceiling-inversion", rung: "R1", severity: "warn", message: `Possible floor/ceiling clamp inversion (${m[0].trim()}).`, fix: "Verify Math.max is used for lower bounds (floors) and Math.min is used for upper bounds (ceilings)." });
  }
  for (const m of masked.matchAll(/\.(?:includes)\s*\(/g)) {
    const idx = m.index ?? 0;
    if (!TS_CASE_SENSITIVE_HEADER.test(raw.slice(Math.max(0, idx - 32), idx + 48))) continue;
    TS_CASE_SENSITIVE_HEADER.lastIndex = 0;
    push(findings, { file: file.rel, line: lineOf(raw, idx), rule: "http-case-sensitive-header-directive", rung: "R1", severity: "warn", message: "HTTP header directive check is case-sensitive without normalizing via .toLowerCase().", fix: "Normalize HTTP header values to lowercase before matching directives." });
  }
}

export function analyzeOssGuards(file: ScannedFile): Finding[] {
  const findings: Finding[] = [];
  const raw = file.content;
  const masked = maskCode(raw, file.language);
  if (file.language === "python") { scanPythonOss(file, raw, masked, findings); return findings; }
  if (file.language === "rust") { scanRustOss(file, raw, masked, findings); return findings; }
  if (file.language === "csharp") { scanCsharpOss(file, raw, masked, findings); return findings; }
  if (file.language === "go") { scanGoOss(file, raw, masked, findings); return findings; }
  if (file.language !== "typescript" && file.language !== "javascript") return findings;
  scanTsJsOssSecurity(file, raw, masked, findings);
  scanTsJsOssCorrectness(file, raw, masked, findings);
  return findings;
}
