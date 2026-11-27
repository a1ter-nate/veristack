import type { ScannedFile } from "@veristack/plugin";
import { maskCode } from "@veristack/plugin";
import type { Finding } from "@veristack/plugin";

const LIFECYCLE_BOOL_NAME =
  /^(?:is_(?:running|armed|stopped|draining|loading|error|errored|pending|complete|completed|closed|cancelled|canceled|connected|disconnected|paused|ready|open|opened|idle|active|busy|starting|stopping|retrying|failed|succeeded|aborted|expired|reverted|locked|unlocked|initialized|disposed|healthy|degraded)|has_(?:started|failed|finished|completed|closed|cancelled|canceled|errored|connected|timed_out|expired|reverted|stopped|succeeded)|was_(?:reverted|cancelled|canceled|stopped|closed|aborted|failed|started)|aborted|armed|draining|saturated|stopping|starting|reverted|expired|active|running|stopped|loading|pending|closed|cancelled|canceled|connected|paused|completed|failed|disposed)$/;

const STATE_DISCRIMINANT = /^(?:status|state|phase|stage|mode)$/;
const CONFIG_TYPE_SUFFIX = /(?:Options|Config|Configuration|Settings|Flags|Args|Params|Props|Input|Query|Filter)$/;
const CANONICAL_TRANSITION = /^(?:transition|reduce|apply_event|next_state|step|step_state|handle_event|__init__)$/;
const PY_MATCH_TARGET = /^(?:(?:self\.)?[a-zA-Z_][a-zA-Z0-9_.]*\.)?_?(?:status|state|phase|stage|kind)$/;

function indentOf(line: string): number {
  let count = 0;
  for (const ch of line) {
    if (ch === " ") count += 1;
    else if (ch === "\t") count += 4;
    else break;
  }
  return count;
}

function collectClassBlocks(lines: readonly string[]): Array<{ name: string; line: number; bodyLines: Array<{ line: number; text: string }> }> {
  const blocks: Array<{ name: string; line: number; bodyLines: Array<{ line: number; text: string }> }> = [];
  for (let i = 0; i < lines.length; i++) {
    const raw = lines[i] ?? "";
    const m = /^(\s*)class\s+([A-Za-z_][A-Za-z0-9_]*)\b/.exec(raw);
    if (!m) continue;
    const baseIndent = indentOf(raw);
    const bodyLines: Array<{ line: number; text: string }> = [];
    for (let j = i + 1; j < lines.length; j++) {
      const next = lines[j] ?? "";
      const trimmed = next.trim();
      if (!trimmed || trimmed.startsWith("#")) continue;
      if (indentOf(next) <= baseIndent) break;
      bodyLines.push({ line: j + 1, text: next });
    }
    blocks.push({ name: m[2] ?? "Class", line: i + 1, bodyLines });
  }
  return blocks;
}

function checkPythonClasses(file: ScannedFile, lines: readonly string[], findings: Finding[]): void {
  if (lines.length === 0) return;
  for (const cls of collectClassBlocks(lines)) {
    if (CONFIG_TYPE_SUFFIX.test(cls.name)) continue;
    const fieldIndent = cls.bodyLines.length > 0 ? indentOf(cls.bodyLines[0]?.text ?? "") : 4;
    const boolFlags: string[] = [];
    const optionalSiblings: string[] = [];
    let discriminant = "";
    for (const entry of cls.bodyLines) {
      if (indentOf(entry.text) !== fieldIndent) continue;
      const trimmed = entry.text.trim();
      if (trimmed.startsWith("def ") || trimmed.startsWith("async def ") || trimmed.startsWith("@")) continue;
      const fieldMatch = /^([a-zA-Z_][a-zA-Z0-9_]*)\s*:\s*([^=#]+)/.exec(trimmed);
      if (!fieldMatch) continue;
      const fieldName = fieldMatch[1] ?? "";
      const typeExpr = (fieldMatch[2] ?? "").trim();
      if (typeExpr === "bool" && LIFECYCLE_BOOL_NAME.test(fieldName)) boolFlags.push(fieldName);
      if (STATE_DISCRIMINANT.test(fieldName) && !/\bOptional\[|\|\s*None\b/.test(typeExpr)) {
        if (!(fieldName === "mode" && CONFIG_TYPE_SUFFIX.test(cls.name))) discriminant = fieldName;
      } else if (/\bOptional\[|\|\s*None\b/.test(typeExpr)) {
        optionalSiblings.push(fieldName);
      }
    }
    if (boolFlags.length >= 2) {
      findings.push({
        id: `SM:py-soup:${file.rel}:${cls.line}`, rule: "implicit-sm-boolean-soup", category: "structure", rung: "R1", severity: "error",
        file: file.rel, line: cls.line,
        message: `Python class '${cls.name}' declares ${boolFlags.length} lifecycle bool fields (${boolFlags.join(", ")}), admitting ${2 ** boolFlags.length} states.`,
        fix: "Collapse lifecycle booleans into a closed @dataclass(frozen=True) union (StateA | StateB | ...) with a pure transition() function.",
      });
    }
    if (discriminant && optionalSiblings.length >= 2 && !/(?:Dto|Response|Request|Row|Payload|Schema|Contract|Message|Event|Params|Options|Config|Settings|Spec)$/i.test(cls.name)) {
      findings.push({
        id: `SM:py-bag:${file.rel}:${cls.line}`, rule: "implicit-sm-optional-bag", category: "structure", rung: "R1", severity: "error",
        file: file.rel, line: cls.line,
        message: `Python class '${cls.name}' pairs discriminant '${discriminant}' with ${optionalSiblings.length} Optional/None payload fields (${optionalSiblings.slice(0, 4).join(", ")}).`,
        fix: "Split into a closed union of frozen dataclasses where each variant carries only its valid fields.",
      });
    }
  }
}

function checkPythonScatteredMutations(file: ScannedFile, lines: readonly string[], findings: Finding[]): void {
  if (lines.length === 0) return;
  let currentFn = "<module>";
  let currentFnIndent = -1;
  const mutatingFns = new Map<string, Set<string>>();
  const firstMutLine = new Map<string, number>();
  for (let i = 0; i < lines.length; i++) {
    const raw = lines[i] ?? "";
    const trimmed = raw.trim();
    if (!trimmed || trimmed.startsWith("#")) continue;
    const indent = indentOf(raw);
    const fnMatch = /^(?:async\s+)?def\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\(/.exec(trimmed);
    if (fnMatch) { currentFn = fnMatch[1] ?? "<fn>"; currentFnIndent = indent; continue; }
    if (currentFnIndent >= 0 && indent <= currentFnIndent && !trimmed.startsWith("@")) { currentFn = "<module>"; currentFnIndent = -1; }
    const assign = /\b(self|[a-z_][a-z0-9_]*)\.(status|state|phase|stage)\s*=\s*(?!=)/.exec(trimmed);
    if (!assign || CANONICAL_TRANSITION.test(currentFn)) continue;
    const key = `${assign[1]}.${assign[2]}`;
    const set = mutatingFns.get(key) ?? new Set<string>();
    set.add(currentFn);
    mutatingFns.set(key, set);
    if (!firstMutLine.has(key)) firstMutLine.set(key, i + 1);
  }
  for (const [key, fns] of mutatingFns.entries()) {
    if (fns.size < 2) continue;
    const line = firstMutLine.get(key) ?? 1;
    findings.push({
      id: `SM:py-mut:${file.rel}:${line}`, rule: "implicit-sm-scattered-mutation", category: "structure", rung: "R1", severity: "error",
      file: file.rel, line,
      message: `State field '${key}' is mutated directly across ${fns.size} distinct Python functions (${[...fns].slice(0, 4).join(", ")}).`,
      fix: "Centralize all state transitions inside a single pure transition(state, event) function.",
    });
  }
}

function collectWildcardCaseBody(lines: readonly string[], startIdx: number, caseIndent: number, firstLine: string): string {
  const caseBody: string[] = [firstLine.replace(/^case\s+_\s*:/, "").trim()];
  for (let k = startIdx + 1; k < lines.length; k++) {
    const inner = lines[k] ?? "";
    const innerTrim = inner.trim();
    if (!innerTrim || innerTrim.startsWith("#")) continue;
    if (indentOf(inner) <= caseIndent) break;
    caseBody.push(innerTrim);
  }
  return caseBody.join(" ");
}

function checkPythonMatches(file: ScannedFile, lines: readonly string[], findings: Finding[]): void {
  if (lines.length === 0) return;
  for (let i = 0; i < lines.length; i++) {
    const raw = lines[i] ?? "";
    const m = /^(\s*)match\s+([a-zA-Z0-9_.]+)\s*:\s*$/.exec(raw);
    if (!m) continue;
    const expr = (m[2] ?? "").trim();
    if (!PY_MATCH_TARGET.test(expr)) continue;
    const baseIndent = indentOf(raw);
    let hasExhaustiveWildcard = false;
    let hasSilentWildcard = false;
    let hasNumericCase = false;
    for (let j = i + 1; j < lines.length; j++) {
      const next = lines[j] ?? "";
      const trimmed = next.trim();
      if (!trimmed || trimmed.startsWith("#")) continue;
      if (indentOf(next) <= baseIndent) break;
      if (/^case\s+\d+\b/.test(trimmed)) hasNumericCase = true;
      if (!/^case\s+_\s*:/.test(trimmed)) continue;
      const joined = collectWildcardCaseBody(lines, j, indentOf(next), trimmed);
      if (hasNumericCase || /\b(?:assert_never|raise)\b/.test(joined)) hasExhaustiveWildcard = true;
      else hasSilentWildcard = true;
    }
    if (hasSilentWildcard || !hasExhaustiveWildcard) {
      findings.push({
        id: `SM:py-match:${file.rel}:${i + 1}`, rule: "implicit-sm-non-exhaustive-switch", category: "structure", rung: "R1", severity: "error",
        file: file.rel, line: i + 1,
        message: hasSilentWildcard
          ? `Python match on '${expr}' uses a silent 'case _:' wildcard instead of assert_never() or raising.`
          : `Python match on '${expr}' lacks an explicit 'case _: assert_never(${expr})' exhaustiveness guard.`,
        fix: `Add 'case _: assert_never(${expr})' (from typing) so mypy/pyright catches unhandled state variants.`,
      });
    }
  }
}

export function lintPythonStateMachines(file: ScannedFile): Finding[] {
  if (!file.content) return [];
  const findings: Finding[] = [];
  const lines = maskCode(file.content, "python").split(/\r?\n/);
  checkPythonClasses(file, lines, findings);
  checkPythonScatteredMutations(file, lines, findings);
  checkPythonMatches(file, lines, findings);
  return findings;
}
