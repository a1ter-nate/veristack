import type { ScannedFile } from "../discover.ts";
import { lineOf, maskCode } from "../test-lexical.ts";
import type { Finding } from "../types.ts";

const JWT_ALG_NONE = /\balgorithms\s*[:=]\s*\[[^\]]*["']none["'][^\]]*\]/gi;
const JWT_VERIFY_SIG_FALSE = /\bverify_signature\s*[:=]\s*(?:false|False)\b/g;
const SQL_CREATE_POLICY = /\bCREATE\s+POLICY\b[\s\S]{0,420}?;/gi;
const SQL_SECURITY_DEFINER = /\bSECURITY\s+DEFINER\b/gi;
const AUTH_ROUTE_PATH = /(?:^|\/)(?:auth|session|csrf|oauth|login|token)[^/]*\.(?:[cm]?[jt]sx?|py)$/i;
const AUTH_GET_HANDLER = /\b(?:(?:app|router)\s*\.\s*get\s*\(\s*["'][^"']*(?:session|csrf|token|userinfo|\/me)[^"']*["']|export\s+(?:async\s+)?function\s+GET\s*\(|@(?:app|router)\s*\.\s*get\s*\(\s*["'][^"']*(?:session|csrf|token|userinfo|\/me)[^"']*["'])/gi;
const DTO_SECRET_LEAK = /\b(?:res\.json|Response\.json|jsonify)\s*\(\s*\{[^}]{0,320}\b(?:passwordHash|password_hash|clientSecret|client_secret|privateKey|private_key)\b/g;

const RUST_UNCHECKED_UTF8 = /(?:\.to_str\s*\(\s*\)\s*\.(?:unwrap|expect)\s*\(|\b(?:str|String)::from_utf8\s*\([^)\n]+\)\s*\.(?:unwrap|expect)\s*\()/g;
const RUST_IMPL_DROP = /\bimpl\b[^{;\n]*\bDrop\s+for\b[^{]*\{/g;
const RUST_REFCELL_BORROW = /\blet\s+(?:mut\s+)?[A-Za-z_][A-Za-z0-9_]*\s*=\s*[^;\n]*\.borrow(?:_mut)?\s*\(\s*\)/g;

const HTTP_VARY_OVERWRITE = /(?:\bheaders\s*\[\s*["']Vary["']\s*\]\s*=|\bsetHeader\s*\(\s*["']Vary["']\s*,)/gi;
const HTTP_DELETE_COOKIE_BARE = /\b(?:delete_cookie|clearCookie)\s*\(\s*["'][^"']+["']\s*\)/g;
const PY_CONTENT_LENGTH_STR = /headers\s*\[\s*["']Content-Length["']\s*\]\s*=\s*(?:str\s*\(\s*)?len\s*\(\s*([A-Za-z_][A-Za-z0-9_.]*)\s*\)/gi;
const PY_ASCII_ENCODE = /\.encode\s*\(\s*["']ascii["']\s*\)/gi;
const TS_CONTENT_LENGTH_LEN = /(?:\bsetHeader\s*\(\s*["']Content-Length["']\s*,\s*(?:String\s*\(\s*)?[A-Za-z_$][A-Za-z0-9_$.]*\.length\b|["']Content-Length["']\s*:\s*(?:String\s*\(\s*)?[A-Za-z_$][A-Za-z0-9_$.]*\.length\b)/gi;
const CS_STREAMWRITER_UTF8_BOM = /\bnew\s+StreamWriter\s*\([^)\n]*\bEncoding\.UTF8\b/g;

const CS_GETORADD_ASYNC = /\.GetOrAdd\s*\([^)\n]*=>[^;\n]*Async\s*\(/g;
const TS_CACHE_SET_ASYNC = /\b(?:cache|inFlight|inflight|pending|promises)\s*\.\s*set\s*\([^,\n]+,\s*(?:fetch\s*\(|[A-Za-z_$][A-Za-z0-9_$.]*Async\s*\(|new\s+Promise\s*\()/g;

const RUNNER_PATH = /(?:^|[/_-])(?:runner|harness|scheduler|watchdog|reporter|plugin)[^/]*\.[cm]?[jt]s$/i;
const BARE_TIMER_CALL = /\b(?:setTimeout|setInterval)\s*\(/g;

const SH_SOURCE_TEST_LIB = /^\s*(?:\.|source)\s+["']?[^"'\n]*test-lib\.sh["']?/m;
const SH_HARNESS_VAR_ASSIGN = /^\s*(?:export\s+)?(?:TEST_DIRECTORY|TRASH_DIRECTORY|TEST_OUTPUT_DIRECTORY)=/gm;
const SH_DEEP_SOCK_PATH = /(?:\$TRASH_DIRECTORY|\$\{TRASH_DIRECTORY\}|\$PWD|\$\{PWD\})[^\s"']*\.sock\b/g;

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
  findings.push({ id: `W7:${rule}:${file}:${line}`, rule, category: "structure", rung, severity, file, line, message, fix });
}

function extractBalancedBlock(code: string, openBraceIdx: number): string {
  let depth = 0;
  for (let i = openBraceIdx; i < code.length && i < openBraceIdx + 2400; i++) {
    const ch = code[i];
    if (ch === "{") depth += 1;
    else if (ch === "}") {
      depth -= 1;
      if (depth === 0) return code.slice(openBraceIdx, i + 1);
    }
  }
  return code.slice(openBraceIdx, openBraceIdx + 600);
}

function scanSqlRls(file: ScannedFile, findings: Finding[]): void {
  const raw = file.content;
  const masked = raw.replace(/--[^\n]*/g, (m) => " ".repeat(m.length)).replace(/\/\*[\s\S]*?\*\//g, (m) => m.replace(/[^\n]/g, " "));

  for (const m of masked.matchAll(SQL_CREATE_POLICY)) {
    const idx = m.index ?? 0;
    const stmt = m[0];
    const hasExplicitRole = /\bTO\s+(?!PUBLIC\b)[A-Za-z_][A-Za-z0-9_]*\b/i.test(stmt);
    const hasNullOrFailOpen = /\bauth\.uid\s*\(\s*\)\s+IS\s+NULL\s+OR\b/i.test(stmt);
    const hasWriteTrue = /\bFOR\s+(?:INSERT|UPDATE|DELETE|ALL)\b/i.test(stmt) && /\b(?:USING|WITH\s+CHECK)\s*\(\s*true\s*\)/i.test(stmt);
    if (!hasExplicitRole || hasNullOrFailOpen || hasWriteTrue) {
      push(
        findings, file.rel, lineOf(raw, idx), "rls-fail-open-null-or-public-role", "R0", "error",
        "RLS CREATE POLICY defaults to PUBLIC role, allows NULL auth.uid(), or permits unconditional true on write operations.",
        "Scope every RLS policy explicitly with 'TO authenticated' (or service role) and require non-null auth.uid() equality.",
      );
    }
  }

  for (const m of masked.matchAll(SQL_SECURITY_DEFINER)) {
    const idx = m.index ?? 0;
    const tail = masked.slice(idx, idx + 800);
    if (!/\bSET\s+search_path\s*=/i.test(tail) && !/\bREVOKE\s+EXECUTE\b/i.test(masked)) {
      push(
        findings, file.rel, lineOf(raw, idx), "rls-fail-open-null-or-public-role", "R0", "error",
        "SECURITY DEFINER SQL function lacks SET search_path and REVOKE EXECUTE FROM PUBLIC.",
        "Pin SET search_path = '' (or pg_catalog, public) and REVOKE EXECUTE ON FUNCTION ... FROM PUBLIC.",
      );
    }
  }
}

function scanShellHarness(file: ScannedFile, findings: Finding[]): void {
  const raw = file.content;
  const sourceMatch = SH_SOURCE_TEST_LIB.exec(raw);
  if (sourceMatch && sourceMatch.index !== undefined) {
    const afterIdx = sourceMatch.index + sourceMatch[0].length;
    const after = raw.slice(afterIdx);
    for (const m of after.matchAll(SH_HARNESS_VAR_ASSIGN)) {
      push(
        findings, file.rel, lineOf(raw, afterIdx + (m.index ?? 0)), "shell-harness-order-and-sockpath", "R1", "warn",
        "Test harness directory variable assigned after sourcing test-lib.sh is silently ignored.",
        "Set TEST_DIRECTORY / TRASH_DIRECTORY before sourcing test-lib.sh.",
      );
    }
  }
  const lines = raw.split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i] ?? "";
    if (line.trim().startsWith("#")) continue;
    if (SH_DEEP_SOCK_PATH.test(line)) {
      SH_DEEP_SOCK_PATH.lastIndex = 0;
      push(
        findings, file.rel, i + 1, "shell-harness-order-and-sockpath", "R1", "warn",
        "Unix domain socket built under $TRASH_DIRECTORY/$PWD can exceed the 104-byte macOS sun_path limit.",
        "Create Unix sockets under a short mktemp -d /tmp/sock.XXXXXX path and clean it up in a trap.",
      );
    }
  }
}

export function analyzeWave7TitansBGuards(file: ScannedFile): Finding[] {
  const findings: Finding[] = [];

  if (file.rel.endsWith(".sql")) {
    scanSqlRls(file, findings);
    return findings;
  }

  if (/\.(?:sh|bash)$/i.test(file.rel)) {
    scanShellHarness(file, findings);
    return findings;
  }

  if (!file.language || file.isTest) return findings;
  const raw = file.content;
  const prodCode = maskCode(raw, file.language, true);
  const prodRaw = raw;

  if (file.language === "rust") {
    for (const m of prodCode.matchAll(RUST_UNCHECKED_UTF8)) {
      push(
        findings, file.rel, lineOf(raw, m.index ?? 0), "rust-unchecked-utf8-or-osstr", "R1", "error",
        `Unchecked UTF-8 conversion (${m[0].trim()}) panics on non-UTF-8 OS paths or wire bytes.`,
        "Propagate Result/Option explicitly or use to_string_lossy() / from_utf8_lossy().",
      );
    }

    for (const m of prodCode.matchAll(RUST_IMPL_DROP)) {
      const idx = m.index ?? 0;
      const braceIdx = idx + m[0].length - 1;
      const block = extractBalancedBlock(prodCode, braceIdx);
      if (/\b(?:tokio::spawn|Handle::current\s*\(|\.unwrap\s*\()/.test(block)) {
        push(
          findings, file.rel, lineOf(raw, idx), "rust-drop-async-spawn-or-unwrap", "R0", "error",
          "Drop implementation invokes tokio::spawn, Handle::current(), or .unwrap(), risking double-panic abort during unwind/shutdown.",
          "Use try_current()/try_send() and ignore or log errors gracefully inside Drop.",
        );
      }
    }

    for (const m of prodCode.matchAll(RUST_REFCELL_BORROW)) {
      const idx = m.index ?? 0;
      const after = prodCode.slice(idx + m[0].length, idx + m[0].length + 280);
      if (!/\bdrop\s*\(/.test(after) && /\b(?:callback|handler|listener|on_[a-z_]+|emit|notify)\s*\(/i.test(after)) {
        push(
          findings, file.rel, lineOf(raw, idx), "rust-reentrant-callback-under-borrow", "R1", "error",
          "Invoking callback while RefCell borrow/borrow_mut guard is still live risks reentrant BorrowMutError panic.",
          "Clone or extract needed state and explicitly drop() the RefCell borrow guard before invoking user callbacks.",
        );
      }
    }
    return findings;
  }

  if (file.language === "csharp") {
    for (const m of prodCode.matchAll(CS_STREAMWRITER_UTF8_BOM)) {
      push(
        findings, file.rel, lineOf(raw, m.index ?? 0), "http-byte-length-and-encoding-drift", "R1", "warn",
        "Encoding.UTF8 emits a UTF-8 BOM in StreamWriter that breaks strict JSON/HTTP/CSV parsers.",
        "Use new UTF8Encoding(encoderShouldEmitUTF8Identifier: false) instead of Encoding.UTF8.",
      );
    }

    for (const m of prodCode.matchAll(CS_GETORADD_ASYNC)) {
      const idx = m.index ?? 0;
      const after = prodCode.slice(idx, idx + 480);
      if (/\b(?:TryRemove|IsFaulted|ContinueWith|Evict|Remove)\b/.test(after)) continue;
      push(
        findings, file.rel, lineOf(raw, idx), "cache-evict-on-fault", "R1", "warn",
        "Caching an async Task via ConcurrentDictionary.GetOrAdd without fault eviction permanently caches transient failures.",
        "Evict faulted/canceled tasks via TryRemove on failure so subsequent callers can recover.",
      );
    }
    return findings;
  }

  if (file.language === "typescript" || file.language === "javascript" || file.language === "python") {
    for (const m of prodRaw.matchAll(JWT_ALG_NONE)) {
      const idx = m.index ?? 0;
      if (prodCode[idx] === " ") continue;
      push(
        findings, file.rel, lineOf(raw, idx), "jwt-unsafe-alg-or-unverified-jwe", "R0", "error",
        "JWT verification allows the unsigned 'none' algorithm, enabling trivial authentication bypass.",
        "Pin an explicit asymmetric allowlist (e.g. ['RS256'] or ['EdDSA']) and reject 'none'.",
      );
    }

    for (const m of prodCode.matchAll(JWT_VERIFY_SIG_FALSE)) {
      push(
        findings, file.rel, lineOf(raw, m.index ?? 0), "jwt-unsafe-alg-or-unverified-jwe", "R0", "error",
        "JWT verification explicitly disables signature verification (verify_signature=false).",
        "Always verify JWT signatures against trusted issuer keys.",
      );
    }

    if (AUTH_ROUTE_PATH.test(file.rel)) {
      for (const m of prodRaw.matchAll(AUTH_GET_HANDLER)) {
        const idx = m.index ?? 0;
        if (prodCode[idx] === " ") continue;
        const win = prodRaw.slice(idx, idx + 650);
        if (/no-store/i.test(win)) continue;
        push(
          findings, file.rel, lineOf(raw, idx), "auth-get-missing-no-store", "R0", "warn",
          "Auth/session/CSRF GET endpoint does not set 'Cache-Control: no-store', risking CDN/proxy token leakage.",
          "Explicitly set 'Cache-Control: no-store, max-age=0' on all session, token, and CSRF responses.",
        );
      }
    }

    for (const m of prodCode.matchAll(DTO_SECRET_LEAK)) {
      push(
        findings, file.rel, lineOf(raw, m.index ?? 0), "secrets-untrusted-ref-eval-or-dto-leak", "R0", "error",
        "HTTP response serialization directly includes sensitive secret/credential fields (passwordHash/clientSecret/privateKey).",
        "Map entities to an explicit allowlisted public DTO before serializing HTTP responses.",
      );
    }

    for (const m of prodRaw.matchAll(HTTP_VARY_OVERWRITE)) {
      const idx = m.index ?? 0;
      if (prodCode[idx] === " ") continue;
      const win = prodCode.slice(Math.max(0, idx - 220), idx + 180);
      if (/(?:append|getHeader|\.get\s*\(|existing_?vary)/i.test(win)) continue;
      push(
        findings, file.rel, lineOf(raw, idx), "http-cookie-vary-and-delete-attrs", "R1", "warn",
        "Overwriting the HTTP Vary header clobbers earlier Vary tokens (e.g. Origin / Accept-Encoding) and causes cache poisoning.",
        "Append to existing Vary header values instead of replacing them.",
      );
    }

    for (const m of prodRaw.matchAll(HTTP_DELETE_COOKIE_BARE)) {
      const idx = m.index ?? 0;
      if (prodCode[idx] === " ") continue;
      push(
        findings, file.rel, lineOf(raw, idx), "http-cookie-vary-and-delete-attrs", "R1", "warn",
        "delete_cookie/clearCookie called without explicit path/domain/secure/samesite attributes may fail to clear scoped cookies.",
        "Pass the exact path, domain, secure, and samesite attributes used when setting the cookie.",
      );
    }
  }

  if (file.language === "python") {
    for (const m of prodRaw.matchAll(PY_CONTENT_LENGTH_STR)) {
      const idx = m.index ?? 0;
      if (prodCode[idx] === " ") continue;
      const win = prodRaw.slice(Math.max(0, idx - 340), idx + 120);
      if (/\.encode\s*\(|bytes\b|bytearray\b/i.test(win)) continue;
      push(
        findings, file.rel, lineOf(raw, idx), "http-byte-length-and-encoding-drift", "R1", "warn",
        "Setting Content-Length from len(str) mismatches UTF-8 byte length on multibyte characters.",
        "Encode the payload to UTF-8 bytes first and use len(payload_bytes) for Content-Length.",
      );
    }

    for (const m of prodRaw.matchAll(PY_ASCII_ENCODE)) {
      const idx = m.index ?? 0;
      if (prodCode[idx] === " ") continue;
      push(
        findings, file.rel, lineOf(raw, idx), "http-byte-length-and-encoding-drift", "R1", "warn",
        "Calling .encode('ascii') without an error policy raises UnicodeEncodeError on non-ASCII input.",
        "Use UTF-8 encoding or specify an explicit error handler / RFC 5987 encoding.",
      );
    }
    return findings;
  }

  if (file.language === "typescript" || file.language === "javascript") {
    for (const m of prodRaw.matchAll(TS_CONTENT_LENGTH_LEN)) {
      const idx = m.index ?? 0;
      if (prodCode[idx] === " ") continue;
      const win = prodCode.slice(Math.max(0, idx - 120), idx + 140);
      if (/\b(?:byteLength|Buffer|Uint8Array|TextEncoder)\b/.test(win)) continue;
      push(
        findings, file.rel, lineOf(raw, idx), "http-byte-length-and-encoding-drift", "R1", "warn",
        "Setting Content-Length from JS string .length measures UTF-16 code units, truncating multibyte UTF-8 bodies.",
        "Use Buffer.byteLength(body, 'utf8') or new TextEncoder().encode(body).byteLength.",
      );
    }

    for (const m of prodCode.matchAll(TS_CACHE_SET_ASYNC)) {
      const idx = m.index ?? 0;
      const after = prodCode.slice(idx, idx + 420);
      if (/\.(?:catch|finally|delete)\s*\(/.test(after)) continue;
      push(
        findings, file.rel, lineOf(raw, idx), "cache-evict-on-fault", "R1", "warn",
        "Caching an in-flight Promise without .catch()/.delete() eviction permanently caches transient rejections.",
        "Attach a rejection handler that deletes the cache entry when the promise fails.",
      );
    }

    if (RUNNER_PATH.test(file.rel)) {
      const hasCapturedTimer = /\b(?:realSetTimeout|nativeSetTimeout|origSetTimeout|capturedSetTimeout|const\s+setTimeout\s*=\s*globalThis\.setTimeout)\b/.test(prodCode);
      if (!hasCapturedTimer) {
        for (const m of prodCode.matchAll(BARE_TIMER_CALL)) {
          push(
            findings, file.rel, lineOf(raw, m.index ?? 0), "runner-capture-timer-globals", "R1", "warn",
            "Test runner/scheduler calls global setTimeout/setInterval directly, which freezes when user code installs fake timers.",
            "Capture const nativeSetTimeout = globalThis.setTimeout at module load time before any fake timers install.",
          );
          break;
        }
      }
    }
  }

  return findings;
}
