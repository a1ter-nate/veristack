import type { DiscoveredRepo, ScannedFile } from "../discover.ts";
import { maskCode } from "../test-lexical.ts";
import type { Finding } from "../types.ts";
import { lintCsharpStateMachines } from "./csharp.ts";
import { lintPythonStateMachines } from "./python.ts";
import { lintRustStateMachines } from "./rust.ts";

const GENERATED_PATH = /(?:^|\/)(?:generated|generated-clients?|codegen|__snapshots__)\/|\.(?:gen|generated)\.[cm]?[jt]sx?$/i;

const LIFECYCLE_BOOL_NAME =
  /^(?:is(?:Running|Armed|Stopped|Draining|Loading|Error|Errored|Pending|Complete|Completed|Closed|Cancelled|Canceled|Connected|Disconnected|Paused|Ready|Open|Opened|Idle|Active|Busy|Starting|Stopping|Retrying|Failed|Succeeded|Aborted|Expired|Reverted|Locked|Unlocked|Initialized|Disposed|Healthy|Degraded)|has(?:Started|Failed|Finished|Completed|Closed|Cancelled|Canceled|Errored|Connected|TimedOut|Expired|Reverted|Stopped|Succeeded)|was(?:Reverted|Cancelled|Canceled|Stopped|Closed|Aborted|Failed|Started)|aborted|armed|draining|saturated|stopping|starting|reverted|expired|active|running|stopped|loading|pending|closed|cancelled|canceled|connected|paused|completed|failed|disposed)$/i;

const STATE_DISCRIMINANT_NAME = /^(?:status|state|phase|stage|mode)$/;
const CONFIG_TYPE_SUFFIX = /(?:Options|Config|Settings|Flags|Args|Params|Props|Input|Query|Filter)$/;
const WIRE_OR_DTO_SUFFIX = /(?:Response|Request|Dto|DTO|Payload|View|Summary|Event|Row)$/;
const EXHAUSTIVE_GUARD = /\b(?:assertNever|exhaustiveCheck|unreachable)\s*\(|:\s*never\b|\bsatisfies\s+never\b/;
const STATE_SWITCH_EXPR = /^(?:[A-Za-z_$][A-Za-z0-9_$.]*\.)?(?:[a-z][A-Za-z0-9]*[Ss]tatus|[a-z][A-Za-z0-9]*[Ss]tate|status|state|phase|stage|kind)$/;
const CANONICAL_TRANSITION_FN = /^(?:transition|reduce|reducer|applyEvent|nextState|stepState|handleEvent)$/i;

function lineOf(text: string, index: number): number {
  let line = 1;
  for (let i = 0; i < index; i++) {
    if (text[i] === "\n") line += 1;
  }
  return line;
}

function maskStringsAndComments(source: string): string {
  return maskCode(source, "typescript");
}

function findMatchingBrace(masked: string, openIdx: number): number {
  let depth = 0;
  for (let i = openIdx; i < masked.length; i++) {
    const ch = masked[i];
    if (ch === "{") depth += 1;
    else if (ch === "}") {
      depth -= 1;
      if (depth === 0) return i;
    }
  }
  return -1;
}

function extractTopLevelMembers(rawBody: string, maskedBody: string): Array<{ raw: string; masked: string }> {
  const members: Array<{ raw: string; masked: string }> = [];
  let depth = 0;
  let start = 0;

  for (let i = 0; i < maskedBody.length; i++) {
    const ch = maskedBody[i];
    if (ch === "{" || ch === "(" || ch === "[" || ch === "<") depth += 1;
    else if (ch === "}" || ch === ")" || ch === "]" || ch === ">") depth = Math.max(0, depth - 1);
    else if (depth === 0 && (ch === ";" || ch === "\n" || ch === ",")) {
      const rawChunk = rawBody.slice(start, i).trim();
      const maskedChunk = maskedBody.slice(start, i).trim();
      if (rawChunk) members.push({ raw: rawChunk, masked: maskedChunk });
      start = i + 1;
    }
  }
  const tailRaw = rawBody.slice(start).trim();
  const tailMasked = maskedBody.slice(start).trim();
  if (tailRaw) members.push({ raw: tailRaw, masked: tailMasked });
  return members;
}

function scanBlockMembers(
  kind: string,
  name: string,
  members: ReadonlyArray<{ raw: string; masked: string }>,
): { lifecycleBools: Set<string>; hasRequiredDiscriminantUnion: boolean; discriminantName: string; optionalSiblings: Set<string> } {
  const lifecycleBools = new Set<string>();
  let hasRequiredDiscriminantUnion = false;
  let discriminantName = "";
  const optionalSiblings = new Set<string>();
  if (members.length === 0) return { lifecycleBools, hasRequiredDiscriminantUnion, discriminantName, optionalSiblings };
  for (const member of members) {
    const propMatch =
      /^(?:(?:public|private|protected|readonly|static|declare|override)\s+)*([A-Za-z_$][A-Za-z0-9_$]*)\s*(\?)?\s*(?::\s*([^=]+?))?(?:\s*=\s*(.+))?$/.exec(member.raw);
    if (!propMatch) continue;
    const propName = propMatch[1] ?? "";
    const isOptional = propMatch[2] === "?";
    const typePart = (propMatch[3] ?? "").trim();
    const initPart = (propMatch[4] ?? "").trim();
    if (propName.includes("(") || /^(?:constructor|get|set|return|if|for|while)$/.test(propName)) continue;
    if ((/\bboolean\b/.test(typePart) || /^(?:true|false)\b/.test(initPart)) && LIFECYCLE_BOOL_NAME.test(propName)) {
      lifecycleBools.add(propName);
    }
    if (kind === "class") continue;
    if (!isOptional && STATE_DISCRIMINANT_NAME.test(propName)) {
      const hasLiteralUnion = /(?:["'`][^"'`]+["'`]\s*\|\s*["'`][^"'`]+["'`])/.test(typePart);
      if (hasLiteralUnion && !(propName === "mode" && CONFIG_TYPE_SUFFIX.test(name))) {
        hasRequiredDiscriminantUnion = true;
        discriminantName = propName;
      }
    } else if (isOptional) {
      optionalSiblings.add(propName);
    }
  }
  return { lifecycleBools, hasRequiredDiscriminantUnion, discriminantName, optionalSiblings };
}

function checkTypeAndClassBlocks(file: ScannedFile, masked: string): Finding[] {
  if (!masked) return [];
  const findings: Finding[] = [];
  const declRegex =
    /\b(?:export\s+)?(?:abstract\s+)?(class|interface|type)\s+([A-Za-z_$][A-Za-z0-9_$]*)(?:\s*<[^>{=]*>)?(?:\s*(?:extends|implements)\s+[^{=]+)?\s*(?:=\s*)?\{/g;
  for (const match of masked.matchAll(declRegex)) {
    const kind = match[1] ?? "";
    const name = match[2] ?? "";
    const declStart = match.index ?? 0;
    const openIdx = declStart + match[0].length - 1;
    const closeIdx = findMatchingBrace(masked, openIdx);
    if (closeIdx < 0) continue;
    const members = extractTopLevelMembers(file.content.slice(openIdx + 1, closeIdx), masked.slice(openIdx + 1, closeIdx));
    const line = lineOf(file.content, declStart);
    const { lifecycleBools, hasRequiredDiscriminantUnion, discriminantName, optionalSiblings } = scanBlockMembers(kind, name, members);
    if (lifecycleBools.size >= 3) {
      const list = [...lifecycleBools].slice(0, 5).join(", ");
      findings.push({
        id: `SM:bool-soup:${file.rel}:${line}`, rule: "implicit-sm-boolean-soup", category: "structure", rung: "R1", severity: "error",
        file: file.rel, line,
        message: `${kind} ${name} declares ${lifecycleBools.size} lifecycle boolean flags (${list}) — admitting ${2 ** lifecycleBools.size} states.`,
        fix: "Collapse lifecycle booleans into a single discriminated union ({ readonly kind: ... }) with an explicit transition table.",
      });
    }
    if (kind !== "class" && !WIRE_OR_DTO_SUFFIX.test(name) && hasRequiredDiscriminantUnion && optionalSiblings.size >= 2) {
      const optList = [...optionalSiblings].slice(0, 5).join(", ");
      findings.push({
        id: `SM:optional-bag:${file.rel}:${line}`, rule: "implicit-sm-optional-bag", category: "structure", rung: "R1", severity: "error",
        file: file.rel, line,
        message: `${kind} ${name} pairs literal-union "${discriminantName}" with ${optionalSiblings.size} optional payload fields (${optList}).`,
        fix: "Split into a discriminated union where each state variant holds only the fields valid in that state.",
      });
    }
  }
  return findings;
}

interface FunctionSpan {
  name: string;
  start: number;
  end: number;
}

function collectFunctionSpans(masked: string): FunctionSpan[] {
  const spans: FunctionSpan[] = [];
  const fnPatterns = [
    /\b(?:export\s+)?(?:async\s+)?function\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*(?:<[^>{]*>)?\s*\([^)]*\)(?:\s*:\s*[^{]+)?\s*\{/g,
    /\b(?:const|let)\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*(?:async\s+)?(?:\([^)]*\)|[A-Za-z_$][A-Za-z0-9_$]*)\s*(?::\s*[^=]+)?=>\s*\{/g,
    /(?:^|\n)\s*(?:(?:public|private|protected|async|override|static)\s+)*([A-Za-z_$][A-Za-z0-9_$]*)\s*(?:<[^>{]*>)?\s*\([^)]*\)(?:\s*:\s*[^{;]+)?\s*\{/g,
  ];
  const keywords = new Set(["if", "for", "while", "switch", "catch", "else", "do", "try", "with"]);
  const seenOpen = new Set<number>();

  for (const regex of fnPatterns) {
    for (const match of masked.matchAll(regex)) {
      const name = match[1] ?? "";
      if (!name || keywords.has(name)) continue;
      const openIdx = (match.index ?? 0) + match[0].length - 1;
      if (seenOpen.has(openIdx)) continue;
      const closeIdx = findMatchingBrace(masked, openIdx);
      if (closeIdx < 0) continue;
      seenOpen.add(openIdx);
      spans.push({ name, start: openIdx, end: closeIdx });
    }
  }

  return spans;
}

function checkScatteredMutations(file: ScannedFile, masked: string): Finding[] {
  const spans = collectFunctionSpans(masked);
  const mutationRegex = /\b(this|[A-Za-z_$][A-Za-z0-9_$]*)\.(?:status|state|phase|stage)\s*=(?!=)/g;
  const mutatingFns = new Map<string, number>();

  for (const match of masked.matchAll(mutationRegex)) {
    const pos = match.index ?? 0;
    const receiver = match[1] ?? "";
    const containing = spans
      .filter((s) => s.start < pos && pos < s.end)
      .sort((a, b) => a.end - a.start - (b.end - b.start))[0];
    if (!containing) continue;
    if (containing.name === "constructor" || CANONICAL_TRANSITION_FN.test(containing.name)) continue;
    if (receiver !== "this") {
      const sigStart = Math.max(0, containing.start - 160);
      const sig = masked.slice(sigStart, containing.start);
      const isParamOrLocal = sig.includes(`${receiver}:`) || sig.includes(`${receiver},`) || sig.includes(`${receiver})`) || masked.slice(containing.start, pos).includes(`const ${receiver}`) || masked.slice(containing.start, pos).includes(`let ${receiver}`);
      if (isParamOrLocal && /(?:row|dto|res|resp|item|entry|record|payload|out|result|draft)/i.test(receiver)) continue;
    }
    if (!mutatingFns.has(containing.name)) {
      mutatingFns.set(containing.name, lineOf(file.content, pos));
    }
  }

  if (mutatingFns.size < 2) return [];
  const entries = [...mutatingFns.entries()];
  const firstLine = entries[0]?.[1] ?? 1;
  const names = entries.map(([name]) => name).slice(0, 5).join(", ");
  return [
    {
      id: `SM:scattered-mutation:${file.rel}:${firstLine}`,
      rule: "implicit-sm-scattered-mutation",
      category: "structure",
      rung: "R1",
      severity: "error",
      file: file.rel,
      line: firstLine,
      message: `Direct state mutation scattered across ${mutatingFns.size} functions/methods (${names}).`,
      fix: "Centralize all state transitions inside one pure transition(state, event) function validated against an explicit ALLOWED_TRANSITIONS table.",
    },
  ];
}

function checkNonExhaustiveSwitches(file: ScannedFile, masked: string): Finding[] {
  if (!masked) return [];
  const findings: Finding[] = [];
  const switchRegex = /\bswitch\s*\(\s*([^)]+?)\s*\)\s*\{/g;

  for (const match of masked.matchAll(switchRegex)) {
    const expr = (match[1] ?? "").trim();
    if (!STATE_SWITCH_EXPR.test(expr)) continue;
    const openIdx = (match.index ?? 0) + match[0].length - 1;
    const closeIdx = findMatchingBrace(masked, openIdx);
    if (closeIdx < 0) continue;

    const rawBody = file.content.slice(openIdx + 1, closeIdx);
    const maskedBody = masked.slice(openIdx + 1, closeIdx);
    const hasDefault = /\bdefault\s*:/.test(maskedBody);
    const hasNumericCases = /\bcase\s+\d+\s*:/.test(maskedBody);
    const hasExhaustive = EXHAUSTIVE_GUARD.test(rawBody);
    if (!hasDefault || (!hasExhaustive && !hasNumericCases)) {
      const line = lineOf(file.content, match.index ?? 0);
      findings.push({
        id: `SM:non-exhaustive:${file.rel}:${line}`,
        rule: "implicit-sm-non-exhaustive-switch",
        category: "structure",
        rung: "R0",
        severity: "error",
        file: file.rel,
        line,
        message: `switch (${expr}) lacks an exhaustiveness guard (never / assertNever) in default.`,
        fix: 'Add default: { const _exhaustive: never = state; throw new Error(`Unhandled state: ${String(_exhaustive)}`); } so new states fail at compile time.',
      });
    }
  }

  return findings;
}

export function lintImplicitStateMachinesInFile(file: ScannedFile): Finding[] {
  const generatedHeader = /(?:@generated|auto-generated|do\s+not\s+edit|generated\s+by\b)/i;
  if (file.isTest || /\.d\.[cm]?ts$|\.pyi$/i.test(file.rel) || (GENERATED_PATH.test(file.rel) && generatedHeader.test(file.content.slice(0, 600)))) return [];
  if (file.language === "csharp") return lintCsharpStateMachines(file);
  if (file.language === "rust") return lintRustStateMachines(file);
  if (file.language === "python") return lintPythonStateMachines(file);
  if (file.language !== "typescript" && file.language !== "javascript") return [];
  const masked = maskStringsAndComments(file.content);
  return [
    ...checkTypeAndClassBlocks(file, masked),
    ...checkScatteredMutations(file, masked),
    ...checkNonExhaustiveSwitches(file, masked),
  ];
}

export function analyzeStateMachines(repo: DiscoveredRepo): Finding[] {
  const findings: Finding[] = [];
  for (const file of repo.files) {
    findings.push(...lintImplicitStateMachinesInFile(file));
  }
  return findings;
}
