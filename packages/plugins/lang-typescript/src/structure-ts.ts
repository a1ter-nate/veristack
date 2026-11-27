import { lineOf, maskCode, type Finding, type ScannedFile } from "@veristack/plugin";

const MAX_EXPORTS = 6;
const EXPORT_DECL = /^\s*export\s+(?:async\s+)?(?:function|const|let|class|enum)\s+[A-Za-z0-9_]+/gm;
const TEST_ONLY_EXPORT =
  /\bexport\s+(?:async\s+)?(?:function|const|let|class|type)\s+[A-Za-z0-9_]*(?:ForTesting|TestOnly|__test|_testOnly|VisibleForTesting)\b/g;
const SWALLOWING_CATCH = /\bcatch\s*(?:\([^)]*\))?\s*\{\s*\}/g;
const CHAINED_AS = /\bas\s+unknown\s+as\b|\bas\s+any\b/g;
const SUPPRESSION_DIRECTIVE =
  /(?:\/\/|\/\*)\s*(?:@ts-(?:ignore|nocheck)\b|(?:oxlint|eslint)-disable(?:-next-line|-line)?\s*(?:\*\/|$|\n)|(?:istanbul|c8|v8)\s+ignore\b)/g;
const CDC_WALL_CLOCK_TS = /\bDate\.now\s*\(\s*\)\s*-\s*[A-Za-z_$][A-Za-z0-9_$.]*/g;

export function scanTsJsStructure(file: ScannedFile): Finding[] {
  if (!file.language || !file.content) return [];
  const findings: Finding[] = [];
  if (!file.isTest) {
    const codeOnly = maskCode(file.content, file.language);
    const exports = codeOnly.match(EXPORT_DECL);
    if (exports && exports.length > MAX_EXPORTS) {
      findings.push({ id: `ST:max-exports:${file.rel}`, rule: "max-exports-per-module", category: "structure", rung: "R1", severity: "warn", file: file.rel, line: 1, message: `${file.rel} exports ${exports.length} declarations (budget: <= ${MAX_EXPORTS}).`, fix: "Hide internal helpers behind a narrower public interface (deep module) or move internals under internal/." });
    }
    for (const match of codeOnly.matchAll(TEST_ONLY_EXPORT)) {
      const line = lineOf(file.content, match.index ?? 0);
      findings.push({ id: `ST:test-seam:${file.rel}:${line}`, rule: "no-test-only-production-seam", category: "structure", rung: "R1", severity: "warn", file: file.rel, line, message: `Test-only export detected in production file: ${match[0].trim()}.`, fix: "Remove test-only production exports and verify behavior through the real public interface." });
    }
    for (const match of codeOnly.matchAll(SWALLOWING_CATCH)) {
      const line = lineOf(file.content, match.index ?? 0);
      findings.push({ id: `ST:swallow-catch:${file.rel}:${line}`, rule: "no-swallowing-catch", category: "structure", rung: "R0", severity: "warn", file: file.rel, line, message: "Empty catch block silently swallows errors.", fix: "Rethrow, return a typed failure result, or handle the specific expected error explicitly." });
    }
    if (file.language === "typescript") {
      for (const match of codeOnly.matchAll(CHAINED_AS)) {
        const line = lineOf(file.content, match.index ?? 0);
        findings.push({ id: `AS:cast:${file.rel}:${line}`, rule: "no-chained-or-any-cast", category: "structure", rung: "R0", severity: "error", file: file.rel, line, message: `Unsafe type escape hatch (${match[0]}) hides real contract.`, fix: "Parse external data once at the boundary with a schema or verifying type guard instead of casting." });
      }
    }
    for (const match of codeOnly.matchAll(CDC_WALL_CLOCK_TS)) {
      if (/(?:retention|ttl|window|max_?age|lookback|stale|grace|cooldown|expir|cutoff|days?_?ms|hours?_?ms|minutes?_?ms|seconds?_?ms|interval_?ms)/i.test(match[0])) continue;
      const line = lineOf(file.content, match.index ?? 0);
      findings.push({ id: `ZD:cdc-clock:${file.rel}:${line}`, rule: "cdc-wall-clock-duration", category: "structure", rung: "R1", severity: "warn", file: file.rel, line, message: `Wall-clock timestamp used for duration/elapsed math (${match[0].trim()}) breaks on NTP jumps or DST (V30 Clock CDC).`, fix: "Use a monotonic clock (performance.now)." });
    }
  }
  let supCount = 0;
  for (const match of file.content.matchAll(SUPPRESSION_DIRECTIVE)) {
    if (++supCount > 3) break;
    const line = lineOf(file.content, match.index ?? 0);
    findings.push({ id: `SU:suppression:${file.rel}:${line}`, rule: "suppression-audit", category: "structure", rung: "R0", severity: "warn", file: file.rel, line, message: "Blanket lint, type, or coverage suppression weakens deterministic gates.", fix: "Fix the underlying defect or scope to a specific rule under a shrink-only suppression ratchet." });
  }
  return findings;
}
