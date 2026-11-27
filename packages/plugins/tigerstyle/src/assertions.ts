import type { ScannedFile } from "@veristack/plugin";
import type { Finding } from "@veristack/plugin";
import {
  extractFunctionUnits,
  hasSafetyDirective,
  lineAtOffset,
  maskTigerCode,
  pushTigerFinding,
  resolveTigerLang,
  type TigerLang,
} from "./helpers.ts";

const MIN_LINES_FOR_ASSERT_DENSITY = 30;
const ASSERT_OR_GUARD_GLOBAL_RE =
  /\b(?:assert|invariant|expect|panic!|unreachable!|assert_eq!|assert_ne!|Effect\.die|Effect\.dieMessage|orDie|ThrowIf|ArgumentException|InvalidOperationException|UnreachableException|throw\s+new\b|raise\s+\w+|if\s*\([^)]*\)\s*(?:\{\s*)?(?:return|throw)|if\s+[^\n:]+:\s*(?:return|raise)|if\s+err\s*!=\s*nil|errors\.New|fmt\.Errorf)\b/g;

interface AssertCtx {
  file: ScannedFile;
  lang: TigerLang;
  lines: readonly string[];
  findings: Finding[];
}

function checkNonHaltingAssertions(ctx: AssertCtx): void {
  if (!ctx.file.content) return;
  const masked = maskTigerCode(ctx.file.content, ctx.lang);
  if (ctx.lang === "typescript" || ctx.lang === "javascript") {
    for (const m of masked.matchAll(/\bconsole\.assert\s*\(/g)) {
      const ln = lineAtOffset(ctx.file.content, m.index ?? 0);
      if (hasSafetyDirective(ctx.lines, ln)) continue;
      pushTigerFinding(ctx.findings, {
        rule: "tiger-non-halting-assert",
        rung: "R0",
        severity: "error",
        file: ctx.file.rel,
        line: ln,
        message: "console.assert() logs and continues execution instead of halting on invariant violation.",
        fix: "Throw a fatal error (assert.ok / invariant / Effect.die) so invalid state halts immediately.",
      });
    }
  }
  if (ctx.lang === "csharp") {
    for (const m of masked.matchAll(/\bDebug\.Assert\s*\(/g)) {
      const ln = lineAtOffset(ctx.file.content, m.index ?? 0);
      if (hasSafetyDirective(ctx.lines, ln)) continue;
      pushTigerFinding(ctx.findings, {
        rule: "tiger-non-halting-assert",
        rung: "R0",
        severity: "error",
        file: ctx.file.rel,
        line: ln,
        message: "Debug.Assert() is stripped in Release builds and does not protect production invariants.",
        fix: "Use explicit runtime guards (ArgumentOutOfRangeException.ThrowIf* / InvalidOperationException).",
      });
    }
  }
}

function checkAssertionDensity(ctx: AssertCtx): void {
  if (!ctx.file.content) return;
  if (ctx.lang === "sql") {
    const maskedSql = maskTigerCode(ctx.file.content, "sql");
    for (const m of maskedSql.matchAll(/\bCREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?([A-Za-z0-9_."]+)\s*\(([\s\S]*?)\)\s*;/gi)) {
      const body = m[2] ?? "";
      const colLines = body.split(",").filter((c) => c.trim().length > 0).length;
      if (colLines >= 4 && !/\b(?:CHECK|NOT\s+NULL|PRIMARY\s+KEY|FOREIGN\s+KEY|UNIQUE)\b/i.test(body)) {
        const ln = lineAtOffset(ctx.file.content, m.index ?? 0);
        pushTigerFinding(ctx.findings, {
          rule: "tiger-low-assertion-density",
          rung: "R1",
          severity: "warn",
          file: ctx.file.rel,
          line: ln,
          message: `SQL table '${m[1]}' defines ${colLines} columns with zero CHECK/NOT NULL/KEY constraints.`,
          fix: "Encode table invariants as explicit NOT NULL, CHECK, PRIMARY KEY, and FOREIGN KEY constraints.",
        });
      }
    }
    return;
  }
  if (ctx.lang === "shell") {
    if (ctx.file.lines >= 20 && !/\bset\s+-[a-z]*e[a-z]*u|\bset\s+-euo\s+pipefail\b/.test(ctx.file.content)) {
      pushTigerFinding(ctx.findings, {
        rule: "tiger-low-assertion-density",
        rung: "R0",
        severity: "warn",
        file: ctx.file.rel,
        line: 1,
        message: "Shell script lacks fail-fast 'set -euo pipefail' invariant guard.",
        fix: "Add 'set -euo pipefail' at the top of the script and validate required args with ${VAR:?}.",
      });
    }
    return;
  }
  const units = extractFunctionUnits(ctx.file);
  for (const unit of units) {
    if (unit.codeLines < MIN_LINES_FOR_ASSERT_DENSITY) continue;
    if (hasSafetyDirective(ctx.lines, unit.startLine)) continue;
    const maskedBody = maskTigerCode(unit.bodyText, ctx.lang);
    const guardMatches = maskedBody.match(ASSERT_OR_GUARD_GLOBAL_RE);
    if (!guardMatches || guardMatches.length === 0) {
      pushTigerFinding(ctx.findings, {
        rule: "tiger-low-assertion-density",
        rung: "R1",
        severity: "warn",
        file: ctx.file.rel,
        line: unit.startLine,
        message: `Function '${unit.name}' (${unit.codeLines}L) contains 0 runtime precondition/invariant assertions.`,
        fix: "Assert preconditions, bounds, and postconditions (positive and negative space) so invalid states fail fast.",
      });
    }
  }
}

function checkPairedWriteReadAssertions(ctx: AssertCtx): void {
  if (ctx.lang !== "typescript" && ctx.lang !== "javascript") return;
  const masked = maskTigerCode(ctx.file.content, ctx.lang);
  const hasWrite = /\b(?:writeFileSync|writeFile)\s*\([^)]*JSON\.stringify\b/.test(masked);
  const readMatch = /\bJSON\.parse\s*\(\s*fs\.readFileSync\b/.exec(masked);
  if (!hasWrite || !readMatch) return;
  const readIdx = readMatch.index;
  const afterRead = masked.slice(readIdx, readIdx + 500);
  const hasReadValidation = /\b(?:isRecord|typeof\s+\w+\s*[!=]==|Array\.isArray|Schema\.decode|zod|parse|assert|invariant|throw\s+new)\b/.test(afterRead);
  if (hasReadValidation) return;
  const ln = lineAtOffset(ctx.file.content, readIdx);
  if (hasSafetyDirective(ctx.lines, ln)) return;
  pushTigerFinding(ctx.findings, {
    rule: "tiger-paired-write-read-assert",
    rung: "R1",
    severity: "warn",
    file: ctx.file.rel,
    line: ln,
    message: "Module serializes JSON to disk and parses it back without paired read-side schema/shape assertions.",
    fix: "Validate parsed JSON shape/invariants on read (paired write+read assertion).",
  });
}

export function analyzeTigerAssertions(file: ScannedFile): Finding[] {
  const lang = resolveTigerLang(file);
  if (!lang) return [];
  const ctx: AssertCtx = { file, lang, lines: file.content.split(/\r?\n/), findings: [] };
  checkNonHaltingAssertions(ctx);
  checkAssertionDensity(ctx);
  checkPairedWriteReadAssertions(ctx);
  return ctx.findings;
}
