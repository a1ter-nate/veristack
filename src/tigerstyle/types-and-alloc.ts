import type { ScannedFile } from "../discover.ts";
import type { Finding } from "../types.ts";
import {
  extractFunctionUnits,
  hasSafetyDirective,
  lineAtOffset,
  maskTigerCode,
  pushTigerFinding,
  resolveTigerLang,
  type TigerLang,
} from "./helpers.ts";

const STARTUP_FN_RE = /^(?:main|init|new|default|build|create|setup|configure|from_|New[A-Z])/;

interface TypesCtx {
  file: ScannedFile;
  lang: TigerLang;
  masked: string;
  lines: readonly string[];
  findings: Finding[];
}

function checkFixedWidthSystems(ctx: TypesCtx): void {
  if (!ctx.masked) return;
  if (ctx.lang === "rust") {
    for (const m of ctx.masked.matchAll(/#\[(?:derive\([^)]*(?:Serialize|Deserialize)[^)]*\)|repr\(C\))\]\s*(?:pub\s+)?struct\s+[A-Za-z_]\w*\s*\{([^}]*)\}/g)) {
      if (/\b(?:usize|isize)\b/.test(m[1] ?? "")) {
        const ln = lineAtOffset(ctx.file.content, m.index ?? 0);
        if (!hasSafetyDirective(ctx.lines, ln)) {
          pushTigerFinding(ctx.findings, { rule: "tiger-fixed-width-types", rung: "R0", severity: "warn", file: ctx.file.rel, line: ln, message: "Serialized/repr(C) Rust struct uses architecture-dependent usize/isize.", fix: "Use fixed-width integer types (u32, u64, i64) for wire and storage layouts." });
        }
      }
    }
    return;
  }
  if (ctx.lang === "csharp") {
    for (const m of ctx.masked.matchAll(/\bunchecked\s*\{/g)) {
      const ln = lineAtOffset(ctx.file.content, m.index ?? 0);
      if (!hasSafetyDirective(ctx.lines, ln)) {
        pushTigerFinding(ctx.findings, { rule: "tiger-fixed-width-types", rung: "R0", severity: "warn", file: ctx.file.rel, line: ln, message: "C# unchecked block silently wraps integer overflow.", fix: "Use checked arithmetic or explicit saturating bounds instead of unchecked blocks." });
      }
    }
    return;
  }
  if (ctx.lang === "go") {
    for (const m of ctx.masked.matchAll(/\btype\s+[A-Za-z_]\w*\s+struct\s*\{([^}]*)\}/g)) {
      const start = m.index ?? 0;
      const rawStruct = ctx.file.content.slice(start, start + m[0].length);
      if (/`json:"[^"]+"`/.test(rawStruct) && /^\s*[A-Z]\w*\s+(?:int|uint)\s+`json:/m.test(rawStruct)) {
        const ln = lineAtOffset(ctx.file.content, start);
        if (!hasSafetyDirective(ctx.lines, ln)) {
          pushTigerFinding(ctx.findings, { rule: "tiger-fixed-width-types", rung: "R0", severity: "warn", file: ctx.file.rel, line: ln, message: "Go wire struct uses architecture-dependent int/uint in JSON-tagged fields.", fix: "Use fixed-width int32/int64/uint32/uint64 for serialized wire structs." });
        }
      }
    }
  }
}

function checkFixedWidthMoney(ctx: TypesCtx): void {
  if (ctx.lang === "sql") {
    for (const m of ctx.masked.matchAll(/\b(?:amount|price|balance|fee|cost|total_cents|salary)\w*\s+(?:FLOAT|REAL|DOUBLE\s+PRECISION)\b/gi)) {
      const ln = lineAtOffset(ctx.file.content, m.index ?? 0);
      if (!hasSafetyDirective(ctx.lines, ln)) {
        pushTigerFinding(ctx.findings, { rule: "tiger-fixed-width-types", rung: "R0", severity: "error", file: ctx.file.rel, line: ln, message: "Monetary SQL column uses IEEE binary floating-point (FLOAT/REAL/DOUBLE).", fix: "Use NUMERIC/DECIMAL or fixed-width BIGINT minor units (cents)." });
      }
    }
    return;
  }
  if (ctx.lang === "python") {
    for (const m of ctx.masked.matchAll(/\b(?:amount|price|balance|fee|cost)\w*\s*=\s*float\s*\(/g)) {
      const ln = lineAtOffset(ctx.file.content, m.index ?? 0);
      if (!hasSafetyDirective(ctx.lines, ln)) {
        pushTigerFinding(ctx.findings, { rule: "tiger-fixed-width-types", rung: "R0", severity: "error", file: ctx.file.rel, line: ln, message: "Monetary Python value converts via binary float().", fix: "Use decimal.Decimal or integer minor units (cents)." });
      }
    }
  }
}

function checkHotPathAllocation(ctx: TypesCtx): void {
  if (ctx.lang !== "rust" && ctx.lang !== "go" && ctx.lang !== "csharp") return;
  const loopAllocRe =
    ctx.lang === "rust"
      ? /\b(?:for|while|loop)\b[^{]*\{[\s\S]{0,240}\b(?:Vec::new|HashMap::new|String::from|Box::new|format!)\s*\(/g
      : ctx.lang === "go"
        ? /\bfor\b[^{]*\{[\s\S]{0,240}\b(?:regexp\.MustCompile|fmt\.Sprintf|make\s*\(\s*\[\]|bytes\.Buffer)/g
        : /\b(?:for|foreach|while)\b[^{]*\{[\s\S]{0,240}\b(?:new\s+List<|new\s+Regex\s*\(|\.ToList\s*\(\s*\)|\.ToArray\s*\(\s*\))/g;
  const units = extractFunctionUnits(ctx.file);
  for (const unit of units) {
    if (STARTUP_FN_RE.test(unit.name)) continue;
    const maskedBody = maskTigerCode(unit.bodyText, ctx.lang);
    for (const m of maskedBody.matchAll(loopAllocRe)) {
      const ln = unit.startLine + lineAtOffset(unit.bodyText, m.index ?? 0) - 1;
      if (hasSafetyDirective(ctx.lines, ln)) continue;
      pushTigerFinding(ctx.findings, {
        rule: "tiger-hot-path-allocation",
        rung: "R0",
        severity: "warn",
        file: ctx.file.rel,
        line: ln,
        message: `Heap allocation inside loop in '${unit.name}' violates startup/preallocated buffer discipline.`,
        fix: "Preallocate buffers/regexes outside the loop or at startup (with_capacity / sync.Pool / ArrayPool / Span).",
      });
      break;
    }
  }
}

function checkExplicitOverImplicit(ctx: TypesCtx): void {
  const checks: ReadonlyArray<{ langs: readonly TigerLang[]; re: RegExp; guard?: RegExp; msg: string; fix: string; sev: "warn" | "error" }> = [
    { langs: ["typescript", "javascript"], re: /\bfetch\s*\(/g, guard: /\b(?:signal|AbortSignal|timeout)\b/i, msg: "fetch() call without explicit AbortSignal/timeout relies on implicit runtime defaults.", fix: "Pass { signal: AbortSignal.timeout(timeoutMsMax) } explicitly.", sev: "warn" },
    { langs: ["rust"], re: /\breqwest::Client::new\s*\(\s*\)/g, msg: "reqwest::Client::new() uses no explicit request/connect timeout.", fix: "Use reqwest::Client::builder().timeout(Duration::from_millis(TIMEOUT_MS_MAX)).build().", sev: "warn" },
    { langs: ["csharp"], re: /\bnew\s+HttpClient\s*\(\s*\)/g, guard: /\bTimeout\s*=/, msg: "new HttpClient() relies on implicit 100s default timeout.", fix: "Set explicit Timeout = TimeSpan.FromMilliseconds(timeoutMsMax) or use IHttpClientFactory.", sev: "warn" },
    { langs: ["go"], re: /\bhttp\.DefaultClient\b/g, msg: "http.DefaultClient has no timeout and relies on implicit global defaults.", fix: "Construct &http.Client{Timeout: timeoutMsMax} explicitly.", sev: "warn" },
    { langs: ["python"], re: /(?:^|[^\w])@retry\s*\(\s*\)/gm, msg: "Bare @retry() decorator lacks explicit stop= max-attempt bound.", fix: "Pass explicit stop=stop_after_attempt(RETRY_COUNT_MAX) and wait=... bounds.", sev: "error" },
    { langs: ["sql"], re: /\bSELECT\s+\*\s+FROM\b/gi, msg: "SELECT * relies on implicit schema column order and fetches unbounded columns.", fix: "List explicit column names in every SELECT query.", sev: "warn" },
    { langs: ["shell"], re: /\bcurl\s+(?![^\n]*(?:--max-time|-m\s))/g, msg: "curl invocation lacks explicit --max-time timeout bound.", fix: "Pass explicit --max-time <seconds> and --fail to curl.", sev: "warn" },
  ];
  for (const c of checks) {
    if (!c.langs.includes(ctx.lang)) continue;
    for (const m of ctx.masked.matchAll(c.re)) {
      const idx = m.index ?? 0;
      const ln = lineAtOffset(ctx.file.content, idx);
      if (hasSafetyDirective(ctx.lines, ln)) continue;
      if (c.guard && c.guard.test(ctx.masked.slice(idx, idx + 260))) continue;
      pushTigerFinding(ctx.findings, { rule: "tiger-explicit-over-implicit", rung: "R0", severity: c.sev, file: ctx.file.rel, line: ln, message: c.msg, fix: c.fix });
    }
  }
}

export function analyzeTigerTypesAndAlloc(file: ScannedFile): Finding[] {
  const lang = resolveTigerLang(file);
  if (!lang) return [];
  const ctx: TypesCtx = {
    file,
    lang,
    masked: maskTigerCode(file.content, lang),
    lines: file.content.split(/\r?\n/),
    findings: [],
  };
  checkFixedWidthSystems(ctx);
  checkFixedWidthMoney(ctx);
  checkHotPathAllocation(ctx);
  checkExplicitOverImplicit(ctx);
  return ctx.findings;
}
