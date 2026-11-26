import type { ScannedFile } from "../discover.ts";
import { lineOf, maskCode } from "../test-lexical.ts";
import type { Finding } from "../types.ts";

const BIDI_CONTROL_CHAR = /[\u202A-\u202E\u2066-\u2069\u200E\u200F\u061C]/g;
const NAN_DIRECT_CMP = /(?:===|!==|==|!=)\s*(?:Number\.NaN\b|NaN\b|math\.NaN\s*\(\s*\)|double\.NaN\b|float\.NaN\b|f32::NAN\b|f64::NAN\b)/g;
const PY_NAN_STR_CMP = /(?:==|!=)\s*float\s*\(\s*["']nan["']\s*\)/gi;
const RUST_PARTIAL_CMP_UNWRAP = /\.partial_cmp\s*\([^)\n]+\)\s*\.(?:unwrap|expect)\s*\(/g;

const URL_SLASH_NO_BACKSLASH =
  /([A-Za-z_][A-Za-z0-9_.]*)\.(?:startsWith|StartsWith|startswith)\s*\(\s*["']\/["']\s*\)[^\n;]{0,80}(?:&&|\band\b)[^\n;]{0,20}(?:!|\bnot\s+)\1\.(?:startsWith|StartsWith|startswith)\s*\(\s*["']\/\/["']\s*\)/g;
const AUTHZ_RAW_PATH_MATCH =
  /(?:r\.URL\.(?:RawPath|EscapedPath\s*\(\s*\))|r\.RequestURI|req\.originalUrl)/g;

const SQL_SELECT_LIMIT_NO_ORDER =
  /\bSELECT\b[^;]{0,420}?\bFROM\b[^;]{0,360}?\b(?:LIMIT\s+[1-9]\d*|OFFSET\s+[1-9]\d*|FETCH\s+(?:FIRST|NEXT)\s+[1-9]\d*)/gi;
const SQL_EQ_NULL = /\b(?:WHERE|AND|OR|HAVING|ON)\b[^;\n]{0,160}?(?:=|!=|<>)\s*NULL\b/gi;
const SQL_NOT_IN_SUBQUERY = /\bNOT\s+IN\s*\(\s*SELECT\s+[A-Za-z_][A-Za-z0-9_.]*\b[^)]{0,220}\)/gi;

const RUST_LET_UNDERSCORE_LOCK =
  /^\s*let\s+_\s*=\s*[^;\n]+\.(?:lock|try_lock|read|try_read|write|try_write)\s*\([^;\n]*\)/gm;
const RUST_ENV_ARGS_OR_VAR =
  /(?:\b(?:std::)?env::args\s*\(\s*\)|\b(?:std::)?env::var\s*\([^)\n]+\)\s*\.(?:unwrap|expect)\s*\()/g;
const RUST_CONDVAR_IF_WAIT = /\bif\b[^{\n]*\{[^}]{0,220}\.wait(?:_timeout)?\s*\(/g;
const RUST_ATOMIC_TOCTOU =
  /\bif\b[^\n]*\.load\s*\(\s*Ordering::\w+\s*\)\s*(?:<|<=|>|>=)[\s\S]{0,200}\.fetch_(?:add|sub)\s*\(/g;

const CS_NARROWING_BEFORE_MIN = /\bMath\.(?:Min|Clamp)\s*\([^)\n]*\(\s*(?:int|Int32)\s*\)\s*[A-Za-z_]/g;
const CS_ARRAYPOOL_RENT = /\bArrayPool<[^>]+>\.Shared\.Rent\s*\(/g;
const CS_TRYPARSE_DECL = /\bTry(?:Parse|Read|Decode)[A-Za-z0-9_]*\s*\([^)]*\)\s*\{/g;
const CS_MONITOR_IF_WAIT = /\bif\s*\([^)\n]*\)\s*\{[^}]{0,220}\bMonitor\.Wait\s*\(/g;
const CS_ATOMIC_TOCTOU =
  /\bif\b[^\n]*Interlocked\.Read\s*\([^)\n]+\)\s*(?:<|<=|>|>=)[\s\S]{0,200}Interlocked\.(?:Increment|Decrement|Add)\s*\(/g;

const PY_DEL_DEF = /^([ \t]*)def\s+__del__\s*\([^)]*\)(?:\s*->\s*[^:\n]+)?\s*:/gm;
const PY_DST_REPLACE_TZ =
  /\.replace\s*\(\s*tzinfo\s*=\s*(?!None\b|UTC\b|datetime\.UTC\b|timezone\.utc\b|datetime\.timezone\.utc\b|pytz\.UTC\b|ZoneInfo\s*\(\s*["']UTC["']\s*\))[^)\n]+\)/g;
const PY_COND_IF_WAIT = /^\s*if\b[^:\n]*:\s*\r?\n(?:[ \t]+[^\n]*\r?\n){0,3}[ \t]+[A-Za-z_][A-Za-z0-9_.]*\.wait\s*\(/gm;

const TS_ANGULAR_DECORATOR = /@(?:Component|Directive|Injectable)\s*\(/;
const TS_SET_INTERVAL = /\bsetInterval\s*\(/g;

const GO_RANGE_RUNELEN =
  /\bfor\s+[A-Za-z_][A-Za-z0-9_]*\s*,\s*([A-Za-z_][A-Za-z0-9_]*)\s*:?=\s*range\b[\s\S]{0,320}\butf8\.RuneLen\s*\(\s*\1\s*\)/g;
const GO_FILEPATH_PATH_CLEAN = /\bfilepath\.(?:Join|Abs)\s*\([^)\n]*\bpath\.Clean\s*\(/g;
const GO_DEFER_CLOSE = /\bdefer\b[^\n]*\.(?:Close|Cancel|Stop|Release)\s*\(/g;
const GO_DEFER_CHAN_CLOSE = /\bdefer\s+close\s*\(\s*([A-Za-z_][A-Za-z0-9_.]*)\s*\)/g;
const GO_FOR_SELECT = /\bfor\s*\{\s*select\s*\{/g;
const GO_CASE_RECV_ONE = /\bcase\s+(?:[A-Za-z_][A-Za-z0-9_]*\s*:?=\s*)?<-\s*([A-Za-z_][A-Za-z0-9_.]*)\s*:/g;
const GO_COND_IF_WAIT = /\bif\b[^{\n]*\{[^}]{0,220}\b[A-Za-z_][A-Za-z0-9_]*\.Wait\s*\(\s*\)/g;
const GO_ATOMIC_TOCTOU =
  /\bif\b[^\n]*(?:\.Load\s*\(\s*\)|atomic\.Load(?:Int|Uint)\w*\s*\([^)\n]+\))\s*(?:<|<=|>|>=)[\s\S]{0,200}(?:\.Add\s*\(|atomic\.Add(?:Int|Uint)\w*\s*\()/g;

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
  findings.push({ id: `W6:${rule}:${file}:${line}`, rule, category: "structure", rung, severity, file, line, message, fix });
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
  return code.slice(openBraceIdx, openBraceIdx + 800);
}

function sliceUntilScopeClose(code: string, fromIdx: number, maxChars: number): string {
  let depth = 0;
  const end = Math.min(code.length, fromIdx + maxChars);
  for (let i = fromIdx; i < end; i++) {
    const ch = code[i];
    if (ch === "{") depth += 1;
    else if (ch === "}") {
      if (depth === 0) return code.slice(fromIdx, i);
      depth -= 1;
    }
  }
  return code.slice(fromIdx, end);
}

function scanSqlTitansA(file: ScannedFile, findings: Finding[]): void {
  const raw = file.content;
  const masked = maskCode(raw, "sql", true);

  for (const m of masked.matchAll(SQL_SELECT_LIMIT_NO_ORDER)) {
    const idx = m.index ?? 0;
    const stmt = m[0];
    if (/\bORDER\s+BY\b/i.test(stmt)) continue;
    const before = masked.slice(Math.max(0, idx - 24), idx);
    if (/\bEXISTS\s*\(\s*$/i.test(before)) continue;
    push(
      findings, file.rel, lineOf(raw, idx), "sql-limit-offset-without-order-by", "R1", "warn",
      "SQL SELECT with LIMIT/OFFSET/FETCH without ORDER BY returns nondeterministic rows across scans.",
      "Add an explicit deterministic ORDER BY (including a unique tie-breaker) before LIMIT/OFFSET.",
    );
  }

  for (const m of masked.matchAll(SQL_EQ_NULL)) {
    push(
      findings, file.rel, lineOf(raw, m.index ?? 0), "sql-null-trap-predicate", "R0", "error",
      "SQL comparison '= NULL' / '!= NULL' evaluates to UNKNOWN under three-valued logic and silently drops rows.",
      "Use 'IS NULL' or 'IS NOT NULL' (or 'IS DISTINCT FROM') instead of '=' / '!=' with NULL.",
    );
  }

  for (const m of masked.matchAll(SQL_NOT_IN_SUBQUERY)) {
    if (/\bIS\s+NOT\s+NULL\b/i.test(m[0])) continue;
    push(
      findings, file.rel, lineOf(raw, m.index ?? 0), "sql-null-trap-predicate", "R1", "warn",
      "SQL 'NOT IN (SELECT ...)' returns zero rows if the subquery emits any NULL value.",
      "Rewrite as 'NOT EXISTS (...)' or filter 'WHERE col IS NOT NULL' inside the subquery.",
    );
  }
}

function scanGoTitansA(file: ScannedFile, raw: string, prodCode: string, prodRaw: string, findings: Finding[]): void {
  for (const m of prodCode.matchAll(GO_RANGE_RUNELEN)) {
    push(
      findings, file.rel, lineOf(raw, m.index ?? 0), "go-range-string-runelen-offset", "R1", "error",
      "Using utf8.RuneLen(r) inside 'for _, r := range s' drifts +2 bytes per invalid UTF-8 byte (RuneError is 3 bytes vs 1-byte step).",
      "Use utf8.DecodeRuneInString(s[pos:]) and advance by the returned byte width.",
    );
  }

  for (const m of prodCode.matchAll(GO_FILEPATH_PATH_CLEAN)) {
    const idx = m.index ?? 0;
    const before = prodRaw.slice(Math.max(0, idx - 280), idx);
    if (/strings\.Contains\s*\([^)]*\\\\|FromSlash|ReplaceAll/.test(before)) continue;
    push(
      findings, file.rel, lineOf(raw, idx), "go-url-path-posix-clean-before-filepath", "R0", "error",
      "Passing POSIX path.Clean() into OS filepath.Join/Abs without rejecting backslashes allows '..\\\\' traversal.",
      "Reject paths containing '\\\\' before calling path.Clean + filepath.Join.",
    );
  }

  for (const m of prodCode.matchAll(GO_DEFER_CLOSE)) {
    const idx = m.index ?? 0;
    const after = sliceUntilScopeClose(prodCode, idx + m[0].length, 800);
    if (/\bselect\s*\{\s*\}/.test(after)) {
      push(
        findings, file.rel, lineOf(raw, idx), "go-defer-before-blocking-select", "R1", "warn",
        "defer Close/Cancel before an infinite blocking 'select {}' never executes, leaking descriptors for process lifetime.",
        "Close the resource explicitly before entering 'select {}' or select on a shutdown context.",
      );
    }
  }

  for (const m of prodCode.matchAll(GO_DEFER_CHAN_CLOSE)) {
    const idx = m.index ?? 0;
    const ch = m[1] ?? "";
    if (!ch) continue;
    const win = prodCode.slice(idx + m[0].length, idx + 800);
    if (/\bsync\.Once\b|\.Do\s*\(/.test(prodCode.slice(Math.max(0, idx - 120), idx + 800))) continue;
    const closeIdx = win.indexOf(`close(${ch})`);
    if (closeIdx >= 0 && !/\bdefer\s+$/.test(win.slice(Math.max(0, closeIdx - 12), closeIdx))) {
      push(
        findings, file.rel, lineOf(raw, idx), "go-channel-double-close", "R0", "error",
        `Channel '${ch}' has both defer close(${ch}) and an explicit close(${ch}) in the same scope, risking panic: close of closed channel.`,
        "Give a single owner responsibility for closing the channel (or guard with sync.Once).",
      );
    }
  }

  for (const m of prodCode.matchAll(GO_FOR_SELECT)) {
    const idx = m.index ?? 0;
    const block = extractBalancedBlock(prodCode, idx + m[0].length - 1);
    const hasCancelExit = /case\s+<-\s*(?:[A-Za-z_][A-Za-z0-9_]*\.Done\(\)|quit|stop|done|cancel)\s*:[\s\S]{0,120}\b(?:return|break)\b/i.test(block);
    for (const cm of block.matchAll(GO_CASE_RECV_ONE)) {
      const ch = cm[1] ?? "";
      if (!ch || /(?:\.C|Done|After|Tick|ctx|stop|quit|cancel)$/i.test(ch)) continue;
      if (hasCancelExit && !prodCode.includes(`close(${ch})`)) continue;
      const bodyStart = (cm.index ?? 0) + cm[0].length;
      const nextCase = block.slice(bodyStart).search(/\b(?:case|default)\b/);
      const body = nextCase >= 0 ? block.slice(bodyStart, bodyStart + nextCase) : block.slice(bodyStart);
      if (/\b(?:return|break)\b/.test(body) || body.includes(`${ch} = nil`)) continue;
      push(
        findings, file.rel, lineOf(raw, idx + (cm.index ?? 0)), "go-select-unchecked-channel-spin", "R1", "error",
        `Unchecked 1-value channel receive from '${ch}' inside 'for { select { ... } }' spins at 100% CPU once closed.`,
        `Use 'v, ok := <-${ch}; if !ok { ${ch} = nil; continue }' or exit on channel close.`,
      );
    }
  }

  if (/\bsync\.Cond\b|\bCond\b/.test(prodCode)) {
    for (const m of prodCode.matchAll(GO_COND_IF_WAIT)) {
      push(
        findings, file.rel, lineOf(raw, m.index ?? 0), "condvar-wait-without-loop", "R1", "error",
        "Waiting on sync.Cond inside an 'if' instead of a 'for' predicate loop breaks on spurious or lost wakeups.",
        "Re-check the wait predicate in a 'for !ready { cond.Wait() }' loop.",
      );
    }
  }

  for (const m of prodCode.matchAll(GO_ATOMIC_TOCTOU)) {
    const idx = m.index ?? 0;
    if (/\bCompareAndSwap\b/.test(prodCode.slice(Math.max(0, idx - 80), idx + 300))) continue;
    push(
      findings, file.rel, lineOf(raw, idx), "atomic-check-then-mutate-toctou", "R1", "error",
      "Checking an atomic Load() before a separate atomic Add() creates a TOCTOU race that can overshoot limits.",
      "Use a CompareAndSwap (CAS) loop or add-first-then-rollback to enforce atomic bounds.",
    );
  }
}

export function analyzeWave6TitansAGuards(file: ScannedFile): Finding[] {
  const findings: Finding[] = [];

  if (file.rel.endsWith(".sql")) {
    scanSqlTitansA(file, findings);
    return findings;
  }

  if (!file.language || file.isTest) return findings;
  const raw = file.content;

  for (const m of raw.matchAll(BIDI_CONTROL_CHAR)) {
    push(
      findings, file.rel, lineOf(raw, m.index ?? 0), "bidi-trojan-source-control-chars", "R0", "error",
      "Raw Unicode BiDi override/isolate control character detected (CVE-2021-42574 Trojan Source risk).",
      "Remove raw BiDi control characters and use explicit \\uXXXX / \\u{XXXX} escape sequences if legitimately needed.",
    );
    break;
  }

  const prodCode = maskCode(raw, file.language, true);
  const prodRaw = raw;

  for (const m of prodCode.matchAll(NAN_DIRECT_CMP)) {
    push(
      findings, file.rel, lineOf(raw, m.index ?? 0), "float-nan-unsafe-cmp", "R1", "error",
      `Direct equality/inequality against NaN (${m[0].trim()}) always evaluates false/true per IEEE-754.`,
      "Use Number.isNaN / math.IsNaN / double.IsNaN / f64::is_nan instead of == or !=.",
    );
  }

  if (file.language === "typescript" || file.language === "javascript" || file.language === "python" || file.language === "csharp") {
    for (const m of prodRaw.matchAll(URL_SLASH_NO_BACKSLASH)) {
      const idx = m.index ?? 0;
      if (prodCode[idx] === " ") continue;
      const around = prodRaw.slice(Math.max(0, idx - 240), idx + m[0].length + 160);
      if (around.includes("\\\\") || /\/[^/\n]*\\\\[^/\n]*\//.test(around) || /IsLocalUrl|IsWellFormedUriString/i.test(around)) {
        continue;
      }
      push(
        findings, file.rel, lineOf(raw, idx), "url-slash-check-missing-backslash", "R0", "error",
        "Local-URL check rejecting '//' without rejecting '\\\\' or '/\\\\' is bypassable in browsers (open redirect).",
        "Reject backslashes ('\\\\') alongside '//' or use the framework's built-in IsLocalUrl validator.",
      );
    }
  }

  if (file.language === "go" || file.language === "typescript" || file.language === "javascript" || file.language === "python") {
    const isAuthzCtx = /(?:auth|acl|rbac|guard|policy|middleware)/i.test(file.rel) || /\b(?:StatusForbidden|StatusUnauthorized|401|403)\b/.test(prodCode);
    if (isAuthzCtx) {
      for (const m of prodCode.matchAll(AUTHZ_RAW_PATH_MATCH)) {
        const idx = m.index ?? 0;
        const win = prodCode.slice(Math.max(0, idx - 120), idx + 240);
        if (!/\b(?:HasPrefix|startsWith|startswith|Match|test|includes)\b/.test(win)) continue;
        if (/\b(?:path\.Clean|normalize|normpath|decodeURIComponent|unquote)\b/.test(win)) continue;
        push(
          findings, file.rel, lineOf(raw, idx), "http-unnormalized-path-authz-match", "R0", "error",
          `Authorization/route guard matches unnormalized raw URL path (${m[0].trim()}), allowing encoded-slash or '..' traversal bypasses.`,
          "Decode and canonicalize the request path (path.Clean / posix.normalize) once before authorization matching.",
        );
      }
    }
  }

  if (file.language === "go") {
    scanGoTitansA(file, raw, prodCode, prodRaw, findings);
    return findings;
  }

  if (file.language === "rust") {
    for (const m of prodCode.matchAll(RUST_PARTIAL_CMP_UNWRAP)) {
      push(
        findings, file.rel, lineOf(raw, m.index ?? 0), "float-nan-unsafe-cmp", "R1", "error",
        "Calling .partial_cmp(...).unwrap()/expect() panics at runtime when NaN enters floating-point comparisons.",
        "Use f64::total_cmp / f32::total_cmp or handle None explicitly.",
      );
    }

    for (const m of prodCode.matchAll(RUST_LET_UNDERSCORE_LOCK)) {
      push(
        findings, file.rel, lineOf(raw, m.index ?? 0), "rust-let-underscore-lock-guard", "R0", "error",
        "Binding a lock guard to 'let _ =' drops the lock immediately at the semicolon, leaving the critical section unlocked.",
        "Bind to a named variable such as 'let _guard = mutex.lock()...;' so the lock lives for the full scope.",
      );
    }

    for (const m of prodCode.matchAll(RUST_ENV_ARGS_OR_VAR)) {
      push(
        findings, file.rel, lineOf(raw, m.index ?? 0), "rust-env-args-or-var-utf8-panic", "R1", "warn",
        `Using ${m[0].trim()} panics or fails on non-UTF-8 OS arguments or environment variables.`,
        "Use std::env::args_os() / std::env::var_os() and handle OsString cleanly.",
      );
    }

    if (/\bCondvar\b/.test(prodCode)) {
      for (const m of prodCode.matchAll(RUST_CONDVAR_IF_WAIT)) {
        if (m[0].includes("wait_while")) continue;
        push(
          findings, file.rel, lineOf(raw, m.index ?? 0), "condvar-wait-without-loop", "R1", "error",
          "Waiting on Condvar inside an 'if' instead of a 'while' loop or wait_while() breaks on spurious wakeups.",
          "Use cvar.wait_while(guard, |state| !ready) or re-check the predicate in a while loop.",
        );
      }
    }

    for (const m of prodCode.matchAll(RUST_ATOMIC_TOCTOU)) {
      const idx = m.index ?? 0;
      if (/\bcompare_exchange\b/.test(prodCode.slice(Math.max(0, idx - 80), idx + 300))) continue;
      push(
        findings, file.rel, lineOf(raw, idx), "atomic-check-then-mutate-toctou", "R1", "error",
        "Checking atomic .load() before a separate .fetch_add()/.fetch_sub() creates a TOCTOU race across threads.",
        "Use fetch_update() / compare_exchange loop to check and update atomically.",
      );
    }
    return findings;
  }

  if (file.language === "csharp") {
    for (const m of prodCode.matchAll(CS_NARROWING_BEFORE_MIN)) {
      push(
        findings, file.rel, lineOf(raw, m.index ?? 0), "csharp-narrowing-cast-before-min", "R1", "error",
        "Narrowing cast to (int) inside Math.Min/Math.Clamp truncates >2 GiB lengths before clamping, risking negative sizes.",
        "Clamp in long first and cast the bounded result: (int)Math.Min(longRemaining, bufferSize).",
      );
    }

    for (const m of prodCode.matchAll(CS_ARRAYPOOL_RENT)) {
      const idx = m.index ?? 0;
      const tail = prodCode.slice(idx, idx + 700);
      if (/\bfinally\b[\s\S]*\.Return\s*\(/.test(tail)) continue;
      push(
        findings, file.rel, lineOf(raw, idx), "csharp-arraypool-unscoped-or-double-return", "R1", "warn",
        "ArrayPool<T>.Shared.Rent() without a matching .Return() inside a finally block leaks pooled buffers on exception paths.",
        "Wrap rented ArrayPool buffers in try { ... } finally { ArrayPool<T>.Shared.Return(buf); }.",
      );
    }

    for (const m of prodCode.matchAll(CS_TRYPARSE_DECL)) {
      const idx = m.index ?? 0;
      const block = extractBalancedBlock(prodCode, idx + m[0].length - 1);
      if (!/\bTimeSpan\.From(?:Seconds|Milliseconds|Microseconds|Minutes|Hours|Days)\s*\(/.test(block)) continue;
      if (/\b(?:MaxValue|MinValue|MaxTimeSpan|OverflowException|ArgumentOutOfRangeException)\b/.test(block)) continue;
      push(
        findings, file.rel, lineOf(raw, idx), "csharp-tryparse-unbounded-timespan", "R1", "warn",
        "TryParse/TryRead method constructs TimeSpan.From* without range checking, violating non-throwing Try* contract on overflow.",
        "Range-check numeric values against TimeSpan.MaxValue/MinValue before calling TimeSpan.From*.",
      );
    }

    for (const m of prodCode.matchAll(CS_MONITOR_IF_WAIT)) {
      push(
        findings, file.rel, lineOf(raw, m.index ?? 0), "condvar-wait-without-loop", "R1", "error",
        "Calling Monitor.Wait() inside an 'if' instead of a 'while' loop breaks on spurious wakeups.",
        "Re-check the predicate inside a 'while (!ready) { Monitor.Wait(sync); }' loop.",
      );
    }

    for (const m of prodCode.matchAll(CS_ATOMIC_TOCTOU)) {
      const idx = m.index ?? 0;
      if (/\bCompareExchange\b/.test(prodCode.slice(Math.max(0, idx - 80), idx + 300))) continue;
      push(
        findings, file.rel, lineOf(raw, idx), "atomic-check-then-mutate-toctou", "R1", "error",
        "Checking Interlocked.Read() before a separate Interlocked.Increment/Add creates a TOCTOU race under contention.",
        "Use an Interlocked.CompareExchange CAS loop to check and update atomically.",
      );
    }
    return findings;
  }

  if (file.language === "python") {
    for (const m of prodRaw.matchAll(PY_NAN_STR_CMP)) {
      const idx = m.index ?? 0;
      if (prodCode[idx] === " ") continue;
      push(
        findings, file.rel, lineOf(raw, idx), "float-nan-unsafe-cmp", "R1", "error",
        "Comparing directly against float('nan') with == or != violates IEEE-754 semantics.",
        "Use math.isnan(value) instead of equality comparison against NaN.",
      );
    }

    for (const m of prodCode.matchAll(PY_DEL_DEF)) {
      const idx = m.index ?? 0;
      const indent = (m[1] ?? "").length;
      const lines = prodCode.slice(idx + m[0].length).split(/\r?\n/).slice(1);
      const bodyLines: string[] = [];
      for (const line of lines) {
        if (line.trim() && line.search(/\S/) <= indent) break;
        bodyLines.push(line);
      }
      const body = bodyLines.join("\n");
      if (/\bis_finalizing\s*\(\s*\)/.test(body)) continue;
      if (/\b(?:import\s+[A-Za-z_]|from\s+[A-Za-z_][A-Za-z0-9_.]*\s+import\b|importlib\.import_module\s*\(|__import__\s*\()/.test(body)) {
        push(
          findings, file.rel, lineOf(raw, idx), "py-finalizer-import-or-unguarded-global", "R1", "error",
          "Importing modules inside __del__ fails or crashes during Python interpreter shutdown when sys.meta_path is cleared.",
          "Move imports to module top-level, prefer context managers (__exit__), or guard with if sys.is_finalizing(): return.",
        );
      }
    }

    for (const m of prodRaw.matchAll(PY_DST_REPLACE_TZ)) {
      const idx = m.index ?? 0;
      if (prodCode[idx] === " ") continue;
      push(
        findings, file.rel, lineOf(raw, idx), "py-datetime-dst-replace-tzinfo", "R1", "warn",
        "Using .replace(tzinfo=...) with a non-UTC timezone shifts wall times silently across DST transitions.",
        "Convert aware datetimes with .astimezone(timezone.utc) or ZoneInfo rather than .replace(tzinfo=...).",
      );
    }

    if (/\bCondition\b/.test(prodCode)) {
      for (const m of prodCode.matchAll(PY_COND_IF_WAIT)) {
        if (/\bwhile\b/.test(m[0])) continue;
        push(
          findings, file.rel, lineOf(raw, m.index ?? 0), "condvar-wait-without-loop", "R1", "error",
          "Calling Condition.wait() inside an 'if' instead of a 'while' loop breaks on spurious wakeups.",
          "Re-check the condition in a 'while not ready: cond.wait()' loop or use cond.wait_for(predicate).",
        );
      }
    }
    return findings;
  }

  if (file.language === "typescript" || file.language === "javascript") {
    if (TS_ANGULAR_DECORATOR.test(prodCode) && !/\bclearInterval\s*\(/.test(prodCode)) {
      for (const m of prodCode.matchAll(TS_SET_INTERVAL)) {
        push(
          findings, file.rel, lineOf(raw, m.index ?? 0), "ts-lifecycle-uncleared-timer", "R1", "warn",
          "Component/service registers setInterval() without clearInterval() in lifecycle teardown, leaking timers after destroy.",
          "Store the timer handle and clear it inside ngOnDestroy() or DestroyRef.onDestroy().",
        );
        break;
      }
    }
  }

  return findings;
}
