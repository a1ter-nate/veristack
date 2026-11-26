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
const PY_OPEN_CALL = /\bopen\s*\(([^)\n]+)\)/g;
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
  if (/^-?\d+(?:\.\d+)?$/.test(firstArg)) return true;
  const isMin = /\bMath\.(?:min|Min)\b/.test(callText.slice(0, open));
  return isMin
    ? /(?:min|Min|floor|Floor)/.test(firstArg)
    : /(?:max|Max|cap|Cap|ceiling|Ceiling)/.test(firstArg);
}
const CS_UNDISPOSED_NEW =
  /^[ \t]*(?!using\b|await\s+using\b|return\b)(?:var|[A-Za-z0-9_.<>]+)\s+[A-Za-z_][A-Za-z0-9_]*\s*=\s*new\s+(?:SqlConnection|NpgsqlConnection|FileStream|StreamReader|StreamWriter|DbCommand|SqlCommand)\s*\(/gm;
const GO_HTTP_CALL = /\b(?:http\.(?:Get|Post|PostForm|Head)|[A-Za-z_][A-Za-z0-9_]*\.Do)\s*\(/g;

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
  findings.push({ id: `OSS:${rule}:${file}:${line}`, rule, category: "structure", rung, severity, file, line, message, fix });
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

function scanPythonOss(file: ScannedFile, raw: string, masked: string, findings: Finding[]): void {
  const lines = raw.split(/\r?\n/);
  for (const m of masked.matchAll(PY_EAGER_ASYNCIO)) {
    const idx = m.index ?? 0;
    const before = raw.slice(Math.max(0, idx - 400), idx);
    const lastDef = [...before.matchAll(/^[ \t]*(async\s+)?def\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(/gm)].pop();
    if (!lastDef || !lastDef[1]) {
      push(
        findings, file.rel, lineOf(raw, idx), "py-no-eager-asyncio-primitive-init", "R1", "error",
        `Eager ${m[0].trim()}) outside an async def binds to the wrong or missing event loop.`,
        "Lazily instantiate asyncio primitives inside an async def or pass the active loop explicitly.",
      );
    }
  }

  for (const m of masked.matchAll(/\bopen\s*\(/g)) {
    const idx = m.index ?? 0;
    const line = lineOf(raw, idx);
    const openMatch = PY_OPEN_CALL.exec(raw.slice(idx, idx + 140));
    PY_OPEN_CALL.lastIndex = 0;
    if (!openMatch) continue;
    const args = openMatch[1] ?? "";
    if (/\bencoding\s*=/.test(args) || /["'][rwxat+]*b[rwxat+]*["']/.test(args)) continue;
    if (/^\s*def\s+open\b|\.\s*open\s*\(/.test(lines[line - 1] ?? "")) continue;
    push(
      findings, file.rel, line, "py-open-missing-encoding", "R1", "warn",
      "Text-mode open() without explicit encoding= depends on OS locale and fails on Windows/UTF-8 files.",
      'Pass encoding="utf-8" (or open in binary mode "rb"/"wb") explicitly.',
    );
  }

  for (const m of masked.matchAll(PY_ORM_DYNAMIC_KWARG)) {
    push(
      findings, file.rel, lineOf(raw, m.index ?? 0), "py-orm-dynamic-kwarg-alias-injection", "R0", "error",
      `Dynamic **kwargs unpacked into ORM query method (${m[0].trim()}) risks SQL alias injection.`,
      "Allowlist explicit static alias names instead of unpacking dynamic dictionaries into ORM query methods.",
    );
  }

  for (const m of masked.matchAll(PY_MKSTEMP_CALL)) {
    const idx = m.index ?? 0;
    if (/\b(?:finally\s*:|with\s+os\.fdopen|os\.close\s*\()/.test(masked.slice(Math.max(0, idx - 120), idx + 320))) continue;
    push(
      findings, file.rel, lineOf(raw, idx), "py-unscoped-fd-or-connection-lifecycle", "R1", "warn",
      "mkstemp() acquires an OS file descriptor without visible try/finally or with os.fdopen cleanup.",
      "Wrap the returned fd in 'with os.fdopen(fd, ...)' or close it in a finally block.",
    );
  }

  for (const m of masked.matchAll(PY_EXCEPT_EXCEPTION)) {
    const idx = m.index ?? 0;
    const block = masked.slice(idx, idx + 360);
    if (!/\.(?:close|unlink|rmtree)\s*\(/.test(block)) continue;
    if (/\bfinally\s*:/.test(block)) continue;
    push(
      findings, file.rel, lineOf(raw, idx), "py-cleanup-require-finally-or-baseexception", "R1", "warn",
      "Resource cleanup inside 'except Exception:' is bypassed by BaseException (CancelledError, KeyboardInterrupt, pytest.skip).",
      "Move resource cleanup into a finally: block or context manager (__exit__).",
    );
  }

  for (const m of raw.matchAll(PY_CASE_SENSITIVE_HEADER)) {
    const idx = m.index ?? 0;
    if ((m[1] ?? "").includes(".lower")) continue;
    const lineStart = raw.lastIndexOf("\n", idx) + 1;
    if (/^\s*#/.test(raw.slice(lineStart, idx))) continue;
    if (masked[idx + (m[0]?.indexOf(" in ") ?? 0) + 1] === " ") continue;
    push(
      findings, file.rel, lineOf(raw, idx), "http-case-sensitive-header-directive", "R1", "warn",
      "HTTP header directive check is case-sensitive without normalizing via .lower()/.toLowerCase().",
      "Normalize HTTP header values to lowercase before matching directives.",
    );
  }
}

function scanRustOss(file: ScannedFile, raw: string, _masked: string, findings: Finding[]): void {
  const prodMasked = maskCode(raw, "rust", true);

  const rustTypeDecl = /\b(?:struct|enum)\s+[A-Za-z_][A-Za-z0-9_]*\b/g;
  for (const m of prodMasked.matchAll(rustTypeDecl)) {
    const declIdx = m.index ?? 0;
    const headerSlice = prodMasked.slice(Math.max(0, declIdx - 420), declIdx);
    const lastSep = Math.max(headerSlice.lastIndexOf("}"), headerSlice.lastIndexOf(";"));
    const attrs = lastSep >= 0 ? headerSlice.slice(lastSep + 1) : headerSlice;
    const denyOffsetInAttrs = attrs.search(/#\[serde\([^\]]*deny_unknown_fields[^\]]*\)\]/);
    if (denyOffsetInAttrs < 0) continue;

    const openBrace = prodMasked.indexOf("{", declIdx + m[0].length);
    const semiBefore = prodMasked.indexOf(";", declIdx + m[0].length);
    if (openBrace < 0 || (semiBefore >= 0 && semiBefore < openBrace)) continue;
    const body = extractBlock(prodMasked, openBrace);
    if (!/#\[serde\([^\]]*flatten[^\]]*\)\]/.test(body)) continue;

    const attrsStart = declIdx - attrs.length;
    push(
      findings, file.rel, lineOf(raw, Math.max(0, attrsStart + denyOffsetInAttrs)), "serde-deny-unknown-with-flatten", "R0", "error",
      "Combining #[serde(deny_unknown_fields)] with #[serde(flatten)] on the same struct/enum is unsupported in Serde and rejects valid payloads at runtime.",
      "Remove deny_unknown_fields when using flatten or replace flatten with an explicit wrapper/custom Deserialize.",
    );
  }

  for (const m of prodMasked.matchAll(RUST_SELECT_NON_CANCEL)) {
    const matchText = m[0];
    const lastArrow = matchText.lastIndexOf("=>");
    const lastEq = matchText.lastIndexOf("=", lastArrow >= 0 ? lastArrow - 1 : matchText.length);
    if (lastArrow >= 0 && lastArrow > lastEq) {
      const afterArrow = matchText.slice(lastArrow + 2);
      if (/\.\s*(?:read_exact|read_to_end|read_to_string|write_all|send_all)\s*\(/.test(afterArrow)) continue;
    }
    push(
      findings, file.rel, lineOf(raw, m.index ?? 0), "rust-select-non-cancel-safe", "R1", "error",
      "Non-cancel-safe async I/O method called inside select! arm — cancelling mid-operation drops buffered data or corrupts framing.",
      "Use cancel-safe primitives (e.g. AsyncReadExt::read with an external buffer or framed streams) inside select!.",
    );
  }

  for (const m of prodMasked.matchAll(RUST_INSTANT_ARITH)) {
    const idx = m.index ?? 0;
    const tail = prodMasked.slice(idx, idx + 80);
    if (/\bInstant::now\s*\(\s*\)\s*\+\s*(?:Duration::from_(?:secs|millis|micros|nanos)\s*\(\s*\d[\d_]*\s*\)|[A-Z][A-Z0-9_]{2,}\b)/.test(tail)) {
      continue;
    }
    push(
      findings, file.rel, lineOf(raw, idx), "rust-unchecked-duration-or-size-arith", "R1", "warn",
      `Unchecked time arithmetic (${m[0].trim()}) can panic on Duration::MAX overflow or backward clock jumps.`,
      "Use checked_add/saturating_duration_since instead of bare +/- or .unwrap() on time deltas.",
    );
  }

  for (const m of prodMasked.matchAll(RUST_POLL_FN)) {
    const start = m.index ?? 0;
    const body = extractBlock(prodMasked, start + m[0].length - 1);
    if (!body || !/\bPoll::Pending\b/.test(body) || /\b(?:cx|waker|Context)\b/.test(body.slice(1))) continue;
    push(
      findings, file.rel, lineOf(raw, start), "rust-poll-pending-no-waker", "R1", "error",
      "Manual poll*() returns Poll::Pending without polling a child future with cx or registering cx.waker(), causing permanent hangs.",
      "Ensure every Poll::Pending path registers a waker via cx.waker() or delegates to a sub-future polled with cx.",
    );
  }

  for (const m of prodMasked.matchAll(/\blet\s+(?:mut\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*[^;\n]+\.(?:lock|write)\s*\(\s*\)/g)) {
    const guardName = m[1] ?? ""; const idx = m.index ?? 0;
    const rawAfter = prodMasked.slice(idx + m[0].length, idx + m[0].length + 280);
    let scopeEnd = rawAfter.length; let bDepth = 0;
    for (let k = 0; k < rawAfter.length; k++) {
      if (rawAfter[k] === "{") bDepth += 1;
      else if (rawAfter[k] === "}" && --bDepth < 0) { scopeEnd = k; break; }
    }
    const after = rawAfter.slice(0, scopeEnd);
    const dropMatch = /\bdrop\s*\(\s*([A-Za-z_][A-Za-z0-9_.]*)\s*\)/.exec(after);
    if (!dropMatch || dropMatch[1] === guardName) continue;
    const dropGuardIdx = after.indexOf(`drop(${guardName})`);
    if (dropGuardIdx >= 0 && dropGuardIdx < (dropMatch.index ?? 0)) continue;
    push(findings, file.rel, lineOf(raw, idx + m[0].length + (dropMatch.index ?? 0)), "rust-drop-under-lock-guard", "R1", "warn", `Dropping '${dropMatch[1]}' while lock guard '${guardName}' is still held risks re-entrant deadlocks if Drop re-acquires the lock.`, `Drop '${guardName}' (or move '${dropMatch[1]}' out of the lock scope) before dropping callbacks/handles/wakers.`);
  }
  for (const m of prodMasked.matchAll(RUST_HASHMAP_ENVS)) {
    push(findings, file.rel, lineOf(raw, m.index ?? 0), "rust-hashmap-deterministic-order", "R1", "warn", "Passing a HashMap into Command::envs produces non-deterministic iteration order across runs.", "Use BTreeMap for deterministic ordering when emitting env vars, CLI args, or serialized snapshots.");
  }
}

export function analyzeOssGuards(file: ScannedFile): Finding[] {
  const findings: Finding[] = [];
  const raw = file.content;
  const masked = maskCode(raw, file.language);

  if (file.language === "python") {
    scanPythonOss(file, raw, masked, findings);
    return findings;
  }
  if (file.language === "rust") {
    scanRustOss(file, raw, masked, findings);
    return findings;
  }

  if (file.language === "csharp") {
    if (CS_EF_CONTEXT.test(masked)) {
      for (const m of masked.matchAll(CS_UNORDERED_SKIP)) {
        const idx = m.index ?? 0;
        const rawBefore = masked.slice(Math.max(0, idx - 220), idx);
        const stmtStart = Math.max(rawBefore.lastIndexOf(";"), rawBefore.lastIndexOf("{"), rawBefore.lastIndexOf("}"));
        const winBefore = stmtStart >= 0 ? rawBefore.slice(stmtStart + 1) : rawBefore;
        const winAfter = masked.slice(idx, idx + 120).split(/[;{}]/)[0] ?? "";
        if (/\.\s*OrderBy(?:Descending)?\s*\(/.test(winBefore)) continue;
        if (!/(?:_db|db|ctx|context|Set\s*<|AsNoTracking|IQueryable|Include\s*\(|ToListAsync|FirstOrDefaultAsync|SingleOrDefaultAsync)/i.test(`${winBefore}${winAfter}`)) continue;
        push(
          findings, file.rel, lineOf(raw, idx), "efcore-unordered-skip-or-assert", "R1", "warn",
          ".Skip() called without a preceding .OrderBy() produces non-deterministic query pagination across DB engines.",
          "Chain a deterministic .OrderBy(...) (with a unique tie-breaker) before .Skip()/.Take().",
        );
      }
    }
    for (const m of masked.matchAll(CS_UNDISPOSED_NEW)) {
      const idx = m.index ?? 0;
      if (/\.\s*Dispose(?:Async)?\s*\(/.test(masked.slice(idx, idx + 320))) continue;
      push(
        findings, file.rel, lineOf(raw, idx), "csharp-undisposed-local-idisp", "R1", "warn",
        "Local IDisposable resource constructed without 'using' risks connection/file-handle leaks.",
        "Declare with 'using var' or 'await using var' so disposal runs deterministically even on exceptions.",
      );
    }
    for (const m of masked.matchAll(FLOOR_CEILING_INVERSION)) {
      if (isSymmetricBoundMath(m[0])) continue;
      push(
        findings, file.rel, lineOf(raw, m.index ?? 0), "math-floor-ceiling-inversion", "R1", "warn",
        `Possible floor/ceiling clamp inversion (${m[0].trim()}).`,
        "Verify Math.Max is used for lower bounds (floors) and Math.Min is used for upper bounds (ceilings).",
      );
    }
    return findings;
  }

  if (file.language === "go") {
    for (const m of masked.matchAll(GO_HTTP_CALL)) {
      const idx = m.index ?? 0;
      const tail = masked.slice(idx, idx + 500);
      if (/\.Do\s*\(\s*func\b/i.test(tail) || /\bonce\.Do\s*\(/i.test(m[0])) continue;
      const lineStart = raw.lastIndexOf("\n", idx) + 1;
      const linePrefix = masked.slice(lineStart, idx);
      if (/^\s*return\b/.test(linePrefix)) continue;
      if (/\.Body\.Close\s*\(/.test(tail)) continue;
      const varMatch = /\b([A-Za-z_]\w*)\s*,\s*[A-Za-z_]\w*\s*:?=\s*$/.exec(linePrefix);
      if (varMatch?.[1] && (tail.includes(`return ${varMatch[1]},`) || tail.includes(`return ${varMatch[1]} `) || tail.includes(`return ${varMatch[1]}\n`))) continue;
      push(
        findings, file.rel, lineOf(raw, idx), "go-unclosed-http-body", "R1", "error",
        "HTTP client call does not close resp.Body, leaking sockets and exhausting keep-alive pools.",
        "Add 'defer resp.Body.Close()' immediately after checking err == nil.",
      );
    }
    return findings;
  }

  if (file.language !== "typescript" && file.language !== "javascript") return findings;

  for (const m of raw.matchAll(UNESCAPED_SCRIPT_INTERP)) {
    const idx = m.index ?? 0;
    if (masked[idx] === " ") continue;
    push(
      findings, file.rel, lineOf(raw, idx), "no-unescaped-script-interpolation", "R0", "error",
      "Raw template interpolation into init script or <script> tag breaks on quotes, </script>, or injection payloads.",
      "Serialize interpolated values with JSON.stringify (escaping '</script>') or pass structured arguments.",
    );
  }

  for (const m of masked.matchAll(PROTO_NULL_LITERAL)) {
    push(
      findings, file.rel, lineOf(raw, m.index ?? 0), "no-proto-null-literal", "R1", "warn",
      "Object literal '{ __proto__: null }' triggers slow-path/serializer quirks compared to Object.create(null) or Map.",
      "Use Object.create(null) or a Map for prototype-free dictionaries.",
    );
  }

  for (const m of masked.matchAll(/\.\s*replace(?:All)?\s*\(/g)) {
    const idx = m.index ?? 0;
    const idm = IDENTITY_REPLACE.exec(raw.slice(idx, idx + 120));
    IDENTITY_REPLACE.lastIndex = 0;
    if (!idm) continue;
    const search = idm[1] ?? idm[2] ?? idm[3];
    const repl = idm[4] ?? idm[5];
    if (search !== undefined && repl !== undefined && search === repl) {
      push(
        findings, file.rel, lineOf(raw, idx), "no-identity-string-replace", "R1", "error",
        `Identity string replace (${idm[0].trim()}) is a no-op bug.`,
        "Fix the intended target/replacement literal or remove the dead replace() call.",
      );
    }
  }

  const literalConstNames = new Set<string>();
  for (const cm of raw.matchAll(/\bconst\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*(?:"[^"\n]*"|'[^'\n]*')/g)) {
    if (cm[1]) literalConstNames.add(cm[1]);
  }

  for (const m of masked.matchAll(/\bnew\s+RegExp\s*\(/g)) {
    const idx = m.index ?? 0;
    const rawSlice = raw.slice(idx, idx + 180);
    const prevWin = raw.slice(Math.max(0, idx - 320), idx);
    if (/\\\$&|escapeRegExp|RegExp\.escape/.test(prevWin)) continue;
    if (!UNESCAPED_REGEXP_TEMPLATE.test(rawSlice)) continue;
    UNESCAPED_REGEXP_TEMPLATE.lastIndex = 0;
    const tmplStart = rawSlice.indexOf("`");
    const tmplEnd = tmplStart >= 0 ? rawSlice.indexOf("`", tmplStart + 1) : -1;
    if (tmplStart >= 0 && tmplEnd > tmplStart) {
      const exprs = [...rawSlice.slice(tmplStart + 1, tmplEnd).matchAll(/\$\{\s*([^}]+?)\s*\}/g)].map((x) => x[1] ?? "");
      if (exprs.length > 0 && exprs.every((e) => /^[A-Za-z_$][A-Za-z0-9_$]*$/.test(e) && literalConstNames.has(e))) {
        continue;
      }
    }
    push(
      findings, file.rel, lineOf(raw, idx), "regex-empty-alternation-or-unescaped", "R1", "warn",
      "Unescaped template interpolation inside new RegExp(`...${...}`) risks ReDoS or metacharacter injection.",
      "Escape dynamic segments with RegExp.escape / an explicit regex-escape helper before compiling.",
    );
  }

function findEmptyAltRegexOffsets(masked: string): number[] {
  const hits: number[] = [];
  let lastNonWs = "";
  for (let i = 0; i < masked.length; i++) {
    const ch = masked[i] ?? "";
    const next = masked[i + 1] ?? "";
    if (ch === "/" && next === "/") {
      while (i < masked.length && masked[i] !== "\n") i += 1;
      continue;
    }
    if (ch === "/" && next === "*") {
      i += 2;
      while (i < masked.length && !(masked[i] === "*" && masked[i + 1] === "/")) i += 1;
      i += 1;
      continue;
    }
    if (ch === "/" && (lastNonWs === "" || "=(,:!&|?;{[}\n".includes(lastNonWs))) {
      let inClass = false;
      let escaped = false;
      let end = -1;
      for (let j = i + 1; j < masked.length; j++) {
        const c = masked[j] ?? "";
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
        const body = masked.slice(i + 1, end);
        if (EMPTY_ALT_INSIDE.test(body)) hits.push(i);
        i = end;
        lastNonWs = ")";
        continue;
      }
    }
    if (ch.trim()) lastNonWs = ch;
  }
  return hits;
}

  for (const offset of findEmptyAltRegexOffsets(masked)) {
    push(
      findings, file.rel, lineOf(raw, offset), "regex-empty-alternation-or-unescaped", "R1", "warn",
      "Regex contains an empty alternation branch (|| or (?:| / |)), silently matching empty strings or causing backtracking.",
      "Replace empty alternation branches with an explicit optional '?' quantifier.",
    );
  }

  for (const m of masked.matchAll(ORM_UNFILTERED_BULK)) {
    const idx = m.index ?? 0;
    if (/updateMany/.test(m[0]) && /\bwhere\s*:/.test(masked.slice(idx, idx + 220))) continue;
    push(
      findings, file.rel, lineOf(raw, idx), "orm-unfiltered-bulk-mutation", "R0", "error",
      `Unfiltered ORM bulk mutation (${m[0].trim()}) affects every row in the table.`,
      "Pass an explicit scoped 'where:' filter (or require an explicit admin-confirmed truncate helper).",
    );
  }

  for (const m of masked.matchAll(/\bcontent\s*:\s*\{/g)) {
    const idx = m.index ?? 0;
    if (!NONCANONICAL_MIME_KEY.test(raw.slice(idx, idx + 120))) continue;
    NONCANONICAL_MIME_KEY.lastIndex = 0;
    push(
      findings, file.rel, lineOf(raw, idx), "schema-noncanonical-content-key", "R1", "warn",
      "Non-canonical MIME key (uppercase, whitespace, or charset param) in route schema content map silently skips validation.",
      'Use canonical lowercase MIME keys without parameters (e.g. "application/json").',
    );
  }

  if (/\bsetHeader\s*\(\s*["']content-length["']/i.test(raw) && /\bsetHeader\s*\(\s*["']transfer-encoding["']/i.test(raw)) {
    if (!/\bremoveHeader\s*\(\s*["'](?:content-length|transfer-encoding)["']/i.test(raw)) {
      const idx = raw.search(/\bsetHeader\s*\(\s*["'](?:content-length|transfer-encoding)["']/i);
      if (masked[Math.max(0, idx)] !== " ") {
        push(
          findings, file.rel, lineOf(raw, Math.max(0, idx)), "http-conflicting-framing-headers", "R0", "error",
          "Module sets both Content-Length and Transfer-Encoding without removing the conflicting framing header (HTTP smuggling risk).",
          "Remove Transfer-Encoding before setting Content-Length (or vice versa) and strip both on 204/304 responses.",
        );
      }
    }
  }

  for (const m of masked.matchAll(TEARDOWN_SEQ_AWAIT)) {
    const idx = m.index ?? 0;
    if (/\btry\s*\{/.test(masked.slice(Math.max(0, idx - 120), idx))) continue;
    push(
      findings, file.rel, lineOf(raw, idx), "require-try-finally-around-teardown", "R1", "warn",
      "Sequential flush/export before close/dispose lacks try...finally — an export error skips close() and leaks resources.",
      "Wrap export/flush in try { ... } finally { await close(); } so teardown always executes.",
    );
  }

  for (const m of masked.matchAll(FLOOR_CEILING_INVERSION)) {
    if (isSymmetricBoundMath(m[0])) continue;
    push(
      findings, file.rel, lineOf(raw, m.index ?? 0), "math-floor-ceiling-inversion", "R1", "warn",
      `Possible floor/ceiling clamp inversion (${m[0].trim()}).`,
      "Verify Math.max is used for lower bounds (floors) and Math.min is used for upper bounds (ceilings).",
    );
  }

  for (const m of masked.matchAll(/\.(?:includes)\s*\(/g)) {
    const idx = m.index ?? 0;
    if (!TS_CASE_SENSITIVE_HEADER.test(raw.slice(Math.max(0, idx - 32), idx + 48))) continue;
    TS_CASE_SENSITIVE_HEADER.lastIndex = 0;
    push(
      findings, file.rel, lineOf(raw, idx), "http-case-sensitive-header-directive", "R1", "warn",
      "HTTP header directive check is case-sensitive without normalizing via .toLowerCase().",
      "Normalize HTTP header values to lowercase before matching directives.",
    );
  }

  return findings;
}
