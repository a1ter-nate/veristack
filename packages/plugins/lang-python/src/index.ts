import { lineOf, maskCode, Plugin, type Finding, type ScannedFile } from "@veristack/plugin";
import { lintPythonStateMachines } from "./python-sm.ts";

export { lintPythonStateMachines };

const PY_TEST_ONLY_EXPORT = /\bdef\s+[a-zA-Z0-9_]*(?:_for_testing|_test_only)\s*\(/g;
const PY_ANY_ESCAPE = /\bcast\s*\(\s*Any\b|:\s*Any\b|->\s*Any\b/g;
const PY_SWALLOWING_EXCEPT = /^\s*except(?:\s+[A-Za-z_][A-Za-z0-9_.]*(?:\s+as\s+[A-Za-z_][A-Za-z0-9_]*)?)?\s*:\s*\r?\n\s*pass\b/gm;
const PY_BARE_SUPPRESSION = /#\s*(?:type:\s*ignore\s*(?:$|\r?\n)|noqa\s*(?:$|\r?\n))/gm;
const PY_PROD_ASSERT = /^\s*assert\s+(?!_?never\b)/gm;
const PY_EXCEPT_OR_CASE_HEAD = /^([ \t]*)(except\b[^\n:]*|case\s+_)\s*:/gm;
const PY_SHAM_RETURN = /\breturn\s+(?:True|(?:JSONResponse\s*\(\s*)?\{[^\n}]*(?:["'](?:accepted|ok|success)["']\s*:\s*True|["']status["']\s*:\s*["']ok["'])[^\n}]*\})|([A-Za-z_]\w*)\s*=\s*\{[^\n}]*(?:["'](?:accepted|ok|success)["']\s*:\s*True|["']status["']\s*:\s*["']ok["'])[^\n}]*\}[\s\S]{0,120}\breturn\s+\1\b/;
const CDC_WALL_CLOCK_PY = /\b(?:datetime\.(?:utc)?now\s*\([^)]*\)|time\.time\s*\(\s*\))\s*-\s*[A-Za-z_][A-Za-z0-9_.]*/g;

function extractPyIndentBlock(raw: string, afterColonIdx: number, baseIndent: number): string {
  const lines = raw.slice(afterColonIdx).split(/\r?\n/).slice(1, 20);
  const body: string[] = [];
  for (const l of lines) {
    if (!l.trim()) { body.push(l); continue; }
    const ind = l.search(/\S/);
    if (ind <= baseIndent) break;
    body.push(l);
  }
  return body.join("\n");
}

export function scanPythonStructure(file: ScannedFile): Finding[] {
  if (!file.content || file.isTest || file.isStub) return [];
  const raw = file.content;
  const masked = maskCode(raw, "python", true);
  if (!masked) return [];
  const findings: Finding[] = [];

  for (const match of masked.matchAll(PY_TEST_ONLY_EXPORT)) {
    const line = lineOf(raw, match.index ?? 0);
    findings.push({ id: `ST:py-test-seam:${file.rel}:${line}`, rule: "no-test-only-production-seam", category: "structure", rung: "R1", severity: "warn", file: file.rel, line, message: `Test-only function in Python production module: ${match[0].trim()}.`, fix: "Remove test-only production backdoors and verify behavior through the public API." });
  }
  const seenPyAnyLines = new Set<number>();
  for (const match of masked.matchAll(PY_ANY_ESCAPE)) {
    const line = lineOf(raw, match.index ?? 0);
    if (seenPyAnyLines.has(line)) continue;
    seenPyAnyLines.add(line);
    findings.push({ id: `AS:py-any:${file.rel}:${line}`, rule: "no-chained-or-any-cast", category: "structure", rung: "R0", severity: "error", file: file.rel, line, message: `Python Any type escape hatch (${match[0].trim()}) disables static type safety.`, fix: "Use object, Protocol, TypeVar, or a validated dataclass/Pydantic model at the boundary." });
  }
  for (const match of raw.matchAll(PY_EXCEPT_OR_CASE_HEAD)) {
    const idx = match.index ?? 0;
    if (masked[idx + (match[1]?.length ?? 0)] === " ") continue;
    const block = extractPyIndentBlock(raw, idx + match[0].length, (match[1] ?? "").length);
    if (!PY_SHAM_RETURN.test(block)) continue;
    const line = lineOf(raw, idx);
    const isCase = (match[2] ?? "").startsWith("case");
    findings.push({
      id: `SHAM:py-${isCase ? "catchall" : "except"}:${file.rel}:${line}`,
      rule: isCase ? "no-catchall-success-stub" : "no-silent-catch-return",
      category: "cheat",
      rung: "R0",
      severity: "error",
      file: file.rel,
      line,
      message: isCase ? "Python wildcard 'case _:' returns fabricated success (True / {'accepted': True})." : "Python except block swallows an exception and returns fabricated success.",
      fix: "Rethrow or return an explicit typed error instead of synthetic success.",
    });
  }
  for (const match of masked.matchAll(PY_SWALLOWING_EXCEPT)) {
    const line = lineOf(raw, match.index ?? 0);
    findings.push({ id: `ST:py-swallow:${file.rel}:${line}`, rule: "no-swallowing-catch", category: "structure", rung: "R0", severity: "error", file: file.rel, line, message: "Python except-pass block silently swallows errors.", fix: "Rethrow, return a typed failure variant, or handle the specific expected exception explicitly." });
  }
  for (const match of raw.matchAll(PY_BARE_SUPPRESSION)) {
    const line = lineOf(raw, match.index ?? 0);
    findings.push({ id: `SU:py-bare:${file.rel}:${line}`, rule: "suppression-audit", category: "structure", rung: "R0", severity: "error", file: file.rel, line, message: "Bare '# type: ignore' or '# noqa' without an error code and concrete reason.", fix: "Fix the diagnostic or scope to a specific code with an inline reason." });
  }
  for (const match of masked.matchAll(PY_PROD_ASSERT)) {
    const line = lineOf(raw, match.index ?? 0);
    findings.push({ id: `ZD:py-assert:${file.rel}:${line}`, rule: "no-release-stripped-assert", category: "structure", rung: "R1", severity: "warn", file: file.rel, line, message: "Python bare 'assert' in production code is stripped under 'python -O' (violates Runtime Jidoka V36).", fix: "Raise an explicit InvariantViolationError (e.g., if not cond: raise InvariantViolationError(...)) so invariants stay active in release." });
  }
  for (const match of masked.matchAll(CDC_WALL_CLOCK_PY)) {
    if (/(?:retention|ttl|window|max_?age|lookback|stale|grace|cooldown|expir|cutoff|days?_?ms|hours?_?ms|minutes?_?ms|seconds?_?ms|interval_?ms)/i.test(match[0])) continue;
    const line = lineOf(raw, match.index ?? 0);
    findings.push({ id: `ZD:cdc-clock:${file.rel}:${line}`, rule: "cdc-wall-clock-duration", category: "structure", rung: "R1", severity: "warn", file: file.rel, line, message: `Wall-clock timestamp used for duration/elapsed math (${match[0].trim()}) breaks on NTP jumps or DST (V30 Clock CDC).`, fix: "Use a monotonic clock (time.monotonic)." });
  }
  return findings;
}

export const langPythonPlugin = Plugin.define({
  id: "veristack.plugin.lang-python",
  setup(ctx) {
    ctx.language.transform((ed) => {
      ed.add({
        id: "python",
        extensions: [".py", ".pyi"],
        scanStructure: scanPythonStructure,
        scanStateMachines: lintPythonStateMachines,
      });
    });
  },
});

export default langPythonPlugin;
