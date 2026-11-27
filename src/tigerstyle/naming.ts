import { parseSync } from "oxc-parser";
import type { ScannedFile } from "../discover.ts";
import type { Finding } from "../types.ts";
import { hasSafetyDirective, lineAtOffset, maskTigerCode, pushTigerFinding, resolveTigerLang, type TigerLang } from "./helpers.ts";

const INVERTED_BIG_ENDIAN_CAMEL =
  /^(?:max|min)(Latency|Timeout|Delay|Retry|Retries|Buffer|Batch|Queue|Chunk|Packet|Payload|Window|Connections|Concurrency|Memory|Size|Bytes|Count|Depth|Age)(Ms|Sec|Seconds|Ns|Us|Bytes|KiB|MiB|Count)?$/;
const INVERTED_BIG_ENDIAN_SNAKE =
  /^(?:max|min)_(latency|timeout|delay|retry|retries|buffer|batch|queue|chunk|packet|payload|window|connections|concurrency|memory|size|bytes|count|depth|age)(?:_(ms|sec|seconds|ns|us|bytes|kib|mib|count))?$/;
const UNIT_IN_MIDDLE_RE = /(?:Timeout|Latency|Delay|Interval|Ttl)In(?:Ms|Sec|Seconds|Minutes)|(?:timeout|latency|delay|interval|ttl)_in_(?:ms|sec|seconds|minutes)/;
const CRYPTIC_ABBREV_RE =
  /^(?:usrAcct|procMsg|calcAmt|bufSz|pktLen|connMgr|reqHdr|respBuf|tmpVal\d+|usr_acct|proc_msg|calc_amt|buf_sz|pkt_len|conn_mgr|req_hdr|resp_buf)$/;
const AMBIGUOUS_UNITLESS_PARAM_RE =
  /\b(timeout|latency|delay|ttl|interval|backoff|sleep|duration)\s*:\s*(?:number|int|i32|i64|u32|u64|float|double|long)\b/;

const ASYMMETRIC_PAIRS: ReadonlyArray<readonly [string, string, string]> = [
  ["start", "finish", "start/end"],
  ["begin", "stop", "begin/end"],
  ["source", "dst", "source/target or src/dst"],
  ["src", "target", "src/dst or source/target"],
  ["read", "send", "read/write or recv/send"],
  ["open", "finish", "open/close"],
];

interface NamingCtx {
  file: ScannedFile;
  lang: TigerLang;
  lines: readonly string[];
  findings: Finding[];
}

function checkIdentifierName(ctx: NamingCtx, ident: string, line: number): void {
  if (hasSafetyDirective(ctx.lines, line)) return;
  if (INVERTED_BIG_ENDIAN_CAMEL.test(ident) || INVERTED_BIG_ENDIAN_SNAKE.test(ident) || UNIT_IN_MIDDLE_RE.test(ident)) {
    const isSnake = ident.includes("_");
    pushTigerFinding(ctx.findings, {
      rule: "tiger-big-endian-naming",
      rung: "R0",
      severity: "warn",
      file: ctx.file.rel,
      line,
      message: `Identifier '${ident}' puts qualifier/unit before the core noun (violates big-endian naming).`,
      fix: isSnake
        ? "Put most significant word first with units and qualifiers as suffixes (e.g., latency_ms_max, timeout_ms)."
        : "Put most significant word first with units and qualifiers as suffixes (e.g., latencyMsMax, timeoutMs).",
    });
    return;
  }
  if (CRYPTIC_ABBREV_RE.test(ident)) {
    pushTigerFinding(ctx.findings, {
      rule: "tiger-big-endian-naming",
      rung: "R0",
      severity: "warn",
      file: ctx.file.rel,
      line,
      message: `Identifier '${ident}' uses cryptic abbreviation.`,
      fix: "Spell out full descriptive domain words (no cryptic vowel-dropped abbreviations).",
    });
  }
}

function checkAsymmetricParamPairs(ctx: NamingCtx, paramNames: readonly string[], line: number): void {
  if (paramNames.length < 2 || hasSafetyDirective(ctx.lines, line)) return;
  const lowerSet = new Set(paramNames.map((n) => n.toLowerCase()));
  for (const [a, b, preferred] of ASYMMETRIC_PAIRS) {
    if (lowerSet.has(a) && lowerSet.has(b)) {
      pushTigerFinding(ctx.findings, {
        rule: "tiger-big-endian-naming",
        rung: "R0",
        severity: "warn",
        file: ctx.file.rel,
        line,
        message: `Paired parameters '${a}' and '${b}' use asymmetric naming.`,
        fix: `Use symmetric, equal-concept paired names (${preferred}).`,
      });
    }
  }
}

function inspectTsFuncParams(ctx: NamingCtx, rec: Record<string, unknown>): void {
  const params = Array.isArray(rec.params) ? rec.params : [];
  const paramNames: string[] = [];
  for (const p of params) {
    if (!p || typeof p !== "object") continue;
    const pr = p as Record<string, unknown>;
    const target = pr.type === "AssignmentPattern" ? (pr.left as Record<string, unknown> | undefined) : pr;
    if (target?.type !== "Identifier" || typeof target.name !== "string" || typeof target.start !== "number") continue;
    const ln = lineAtOffset(ctx.file.content, target.start);
    paramNames.push(target.name);
    checkIdentifierName(ctx, target.name, ln);
    if (typeof pr.start === "number" && typeof pr.end === "number") {
      const paramSlice = ctx.file.content.slice(pr.start, pr.end);
      if (AMBIGUOUS_UNITLESS_PARAM_RE.test(paramSlice) && !hasSafetyDirective(ctx.lines, ln)) {
        pushTigerFinding(ctx.findings, {
          rule: "tiger-big-endian-naming",
          rung: "R0",
          severity: "warn",
          file: ctx.file.rel,
          line: ln,
          message: `Numeric duration parameter '${target.name}' omits unit suffix.`,
          fix: `Append explicit unit suffix (e.g. '${target.name}Ms' or '${target.name}Sec').`,
        });
      }
    }
  }
  if (typeof rec.start === "number") checkAsymmetricParamPairs(ctx, paramNames, lineAtOffset(ctx.file.content, rec.start));
}

function scanTsNaming(ctx: NamingCtx): void {
  let parsed: ReturnType<typeof parseSync>;
  try { parsed = parseSync(ctx.file.rel, ctx.file.content); } catch { return; }
  const stack: unknown[] = [parsed.program];
  let visited = 0;
  while (stack.length > 0 && visited < 60_000) {
    visited += 1;
    const cur = stack.pop();
    if (!cur || typeof cur !== "object") continue;
    const rec = cur as Record<string, unknown>;
    const t = typeof rec.type === "string" ? rec.type : "";
    if (t === "VariableDeclarator") {
      const id = rec.id as Record<string, unknown> | undefined;
      if (id?.type === "Identifier" && typeof id.name === "string" && typeof id.start === "number") {
        checkIdentifierName(ctx, id.name, lineAtOffset(ctx.file.content, id.start));
      }
    } else if (t === "FunctionDeclaration" || t === "FunctionExpression" || t === "ArrowFunctionExpression") {
      inspectTsFuncParams(ctx, rec);
    }
    for (const val of Object.values(rec)) {
      if (Array.isArray(val)) for (const item of val) stack.push(item);
      else if (val && typeof val === "object") stack.push(val);
    }
  }
}

function scanNonTsNaming(ctx: NamingCtx): void {
  if (!ctx.file.content) return;
  const masked = maskTigerCode(ctx.file.content, ctx.lang);
  const declRe =
    ctx.lang === "sql"
      ? /^\s*([a-zA-Z_]\w*)\s+(?:INT|BIGINT|INTEGER|NUMERIC|DECIMAL|REAL|FLOAT|DOUBLE)/gim
      : /\b(?:let\s+(?:mut\s+)?|const\s+|var\s+|local\s+)?([a-zA-Z_]\w*)\s*(?::=|[:=])/g;
  const seen = new Set<string>();
  for (const m of masked.matchAll(declRe)) {
    const ident = m[1] ?? "";
    if (!ident) continue;
    const ln = lineAtOffset(ctx.file.content, m.index ?? 0);
    const key = `${ident}:${ln}`;
    if (seen.has(key)) continue;
    seen.add(key);
    checkIdentifierName(ctx, ident, ln);
  }
  for (const m of masked.matchAll(new RegExp(AMBIGUOUS_UNITLESS_PARAM_RE.source, "g"))) {
    const ln = lineAtOffset(ctx.file.content, m.index ?? 0);
    if (hasSafetyDirective(ctx.lines, ln)) continue;
    pushTigerFinding(ctx.findings, {
      rule: "tiger-big-endian-naming",
      rung: "R0",
      severity: "warn",
      file: ctx.file.rel,
      line: ln,
      message: `Numeric duration identifier '${m[1]}' omits unit suffix.`,
      fix: "Append explicit unit suffix (_ms / _sec / Ms / Sec).",
    });
  }
}

export function analyzeTigerNaming(file: ScannedFile): Finding[] {
  const lang = resolveTigerLang(file);
  if (!lang) return [];
  const ctx: NamingCtx = { file, lang, lines: file.content.split(/\r?\n/), findings: [] };
  if (lang === "typescript" || lang === "javascript") scanTsNaming(ctx);
  else scanNonTsNaming(ctx);
  return ctx.findings;
}
