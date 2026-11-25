import type { ScannedFile } from "../discover.ts";
import type { Finding } from "../types.ts";

const LIFECYCLE_BOOL_NAME =
  /^(?:is(?:Running|Armed|Stopped|Draining|Loading|Error|Errored|Pending|Complete|Completed|Closed|Cancelled|Canceled|Connected|Disconnected|Paused|Ready|Open|Opened|Idle|Active|Busy|Starting|Stopping|Retrying|Failed|Succeeded|Aborted|Expired|Reverted|Locked|Unlocked|Initialized|Disposed|Healthy|Degraded)|has(?:Started|Failed|Finished|Completed|Closed|Cancelled|Canceled|Errored|Connected|TimedOut|Expired|Reverted|Stopped|Succeeded)|was(?:Reverted|Cancelled|Canceled|Stopped|Closed|Aborted|Failed|Started)|aborted|armed|draining|saturated|stopping|starting|reverted|expired|active|running|stopped|loading|pending|closed|cancelled|canceled|connected|paused|completed|failed|disposed)$/i;

const STATE_DISCRIMINANT = /^(?:Status|State|Phase|Stage|Mode)$/;
const CONFIG_TYPE_SUFFIX = /(?:Options|Config|Configuration|Settings|Flags|Args|Params|Props|Input|Query|Filter)$/;
const CANONICAL_TRANSITION = /^(?:Transition|Reduce|ApplyEvent|NextState|StepState|HandleEvent|TryTransition)$/i;
const CS_SWITCH_TARGET = /^(?:(?:this\.)?[A-Za-z_][A-Za-z0-9_.]*\.)?(?:_?(?:status|state|phase|stage|kind))$/i;
const CS_EXHAUSTIVE_THROW = /\bthrow\s+new\s+[A-Za-z0-9_.]*(?:SwitchExpressionException|UnreachableException|ArgumentOutOfRangeException|InvalidOperationException)\b|\bthrow\s+/;

function lineOf(text: string, index: number): number {
  let line = 1;
  for (let i = 0; i < index; i++) {
    if (text[i] === "\n") line += 1;
  }
  return line;
}

function maskCsharp(source: string): string {
  const out = [...source];
  let quote = "";
  let verbatim = false;
  let escaped = false;
  let lineComment = false;
  let blockComment = false;

  for (let i = 0; i < source.length; i++) {
    const ch = source[i] ?? "";
    const next = source[i + 1] ?? "";
    if (lineComment) {
      if (ch === "\n") lineComment = false;
      else out[i] = " ";
      continue;
    }
    if (blockComment) {
      if (ch === "*" && next === "/") {
        out[i] = " ";
        out[i + 1] = " ";
        blockComment = false;
        i += 1;
      } else if (ch !== "\n") {
        out[i] = " ";
      }
      continue;
    }
    if (quote) {
      if (ch !== "\n" && ch !== "\r") out[i] = " ";
      if (verbatim && ch === '"' && next === '"') {
        out[i + 1] = " ";
        i += 1;
        continue;
      }
      if (escaped) {
        escaped = false;
        continue;
      }
      if (!verbatim && ch === "\\") {
        escaped = true;
        continue;
      }
      if (ch === quote) {
        quote = "";
        verbatim = false;
      }
      continue;
    }
    if (ch === "/" && next === "/") {
      out[i] = " ";
      out[i + 1] = " ";
      lineComment = true;
      i += 1;
      continue;
    }
    if (ch === "/" && next === "*") {
      out[i] = " ";
      out[i + 1] = " ";
      blockComment = true;
      i += 1;
      continue;
    }
    if (ch === '"' && source.slice(i, i + 3) === '"""') {
      const end = source.indexOf('"""', i + 3);
      const stop = end < 0 ? source.length : end + 3;
      for (let k = i; k < stop; k++) {
        if (source[k] !== "\n" && source[k] !== "\r") out[k] = " ";
      }
      i = stop - 1;
      continue;
    }
    if ((ch === "@" && next === '"') || (ch === "$" && next === "@" && source[i + 2] === '"') || (ch === "@" && next === "$" && source[i + 2] === '"')) {
      const offset = next === '"' ? 1 : 2;
      for (let k = i; k <= i + offset; k++) out[k] = " ";
      quote = '"';
      verbatim = true;
      i += offset;
      continue;
    }
    if (ch === '"' || ch === "'") {
      quote = ch;
      out[i] = " ";
    }
  }
  return out.join("");
}

function findMatching(masked: string, openIdx: number, openChar: string, closeChar: string): number {
  let depth = 0;
  for (let i = openIdx; i < masked.length; i++) {
    const ch = masked[i];
    if (ch === openChar) depth += 1;
    else if (ch === closeChar) {
      depth -= 1;
      if (depth === 0) return i;
    }
  }
  return -1;
}

function splitTopLevel(text: string, sep: string): string[] {
  const parts: string[] = [];
  let depth = 0;
  let start = 0;
  for (let i = 0; i < text.length; i++) {
    const ch = text[i];
    if (ch === "(" || ch === "{" || ch === "[" || ch === "<") depth += 1;
    else if (ch === ")" || ch === "}" || ch === "]" || ch === ">") depth = Math.max(0, depth - 1);
    else if (depth === 0 && ch === sep) {
      parts.push(text.slice(start, i).trim());
      start = i + 1;
    }
  }
  const tail = text.slice(start).trim();
  if (tail) parts.push(tail);
  return parts;
}

function collectCsharpProperties(headerParams: string, bodyText: string): Array<{ type: string; name: string; nullable: boolean }> {
  const items: Array<{ type: string; name: string; nullable: boolean }> = [];

  if (headerParams.trim()) {
    for (const param of splitTopLevel(headerParams, ",")) {
      const cleaned = param.replace(/^\[[^\]]+\]\s*/g, "").replace(/\s*=.*$/, "").trim();
      const m = /^(?:(?:required|in|out|ref)\s+)*([A-Za-z_][A-Za-z0-9_.<>,\s]*?)(\?)?\s+([A-Za-z_][A-Za-z0-9_]*)$/.exec(cleaned);
      if (m) {
        items.push({ type: (m[1] ?? "").trim(), name: m[3] ?? "", nullable: m[2] === "?" });
      }
    }
  }

  if (bodyText.trim()) {
    let depth = 0;
    let start = 0;
    const chunks: string[] = [];
    for (let i = 0; i < bodyText.length; i++) {
      const ch = bodyText[i];
      if (ch === "{") depth += 1;
      else if (ch === "}") {
        depth = Math.max(0, depth - 1);
        if (depth === 0) {
          chunks.push(bodyText.slice(start, i + 1).trim());
          start = i + 1;
        }
      } else if (depth === 0 && ch === ";") {
        chunks.push(bodyText.slice(start, i).trim());
        start = i + 1;
      }
    }

    for (const chunk of chunks) {
      if (/\b(?:class|record|struct|interface|enum|namespace)\b/.test(chunk)) continue;
      if (/\([^)]*\)\s*(?:\{|=>)/.test(chunk)) continue;
      const cleaned = chunk.replace(/^\s*(?:\[[^\]]+\]\s*)+/g, "").trim();
      const prop =
        /^(?:(?:public|private|protected|internal|readonly|static|required|virtual|override|sealed|new|volatile)\s+)+([A-Za-z_][A-Za-z0-9_.<>,\s]*?)(\?)?\s+([A-Za-z_][A-Za-z0-9_]*)\s*(?:\{|=|$)/.exec(
          cleaned,
        );
      if (prop) {
        const type = (prop[1] ?? "").trim();
        const name = prop[3] ?? "";
        if (!/^(?:void|Task|ValueTask)$/.test(type) && !/^(?:return|throw|if|for|while|switch)$/.test(name)) {
          items.push({ type, name, nullable: prop[2] === "?" });
        }
      }
    }
  }

  return items;
}

function checkCsharpTypes(file: ScannedFile, masked: string): Finding[] {
  const findings: Finding[] = [];
  const typeRegex =
    /\b(?:(?:public|internal|private|protected|sealed|abstract|partial|readonly|static|file)\s+)*(record\s+struct|record\s+class|record|class|struct)\s+([A-Za-z_][A-Za-z0-9_]*)(?:<[^>{;(]*>)?/g;

  for (const match of masked.matchAll(typeRegex)) {
    const kind = (match[1] ?? "").replace(/\s+/g, " ");
    const name = match[2] ?? "";
    const start = match.index ?? 0;
    let cursor = start + match[0].length;
    while (cursor < masked.length && /\s/.test(masked[cursor] ?? "")) cursor += 1;

    let headerParams = "";
    if (masked[cursor] === "(") {
      const closeParen = findMatching(masked, cursor, "(", ")");
      if (closeParen < 0) continue;
      headerParams = file.content.slice(cursor + 1, closeParen);
      cursor = closeParen + 1;
    }

    while (cursor < masked.length && masked[cursor] !== "{" && masked[cursor] !== ";") cursor += 1;
    let bodyText = "";
    if (masked[cursor] === "{") {
      const closeBrace = findMatching(masked, cursor, "{", "}");
      if (closeBrace < 0) continue;
      bodyText = masked.slice(cursor + 1, closeBrace);
    }

    const props = collectCsharpProperties(headerParams, bodyText);
    const lifecycleBools = new Set<string>();
    let discriminantName = "";
    const nullableSiblings = new Set<string>();

    for (const prop of props) {
      const bareName = prop.name.replace(/^_+/, "");
      if (prop.type === "bool" && LIFECYCLE_BOOL_NAME.test(bareName)) {
        lifecycleBools.add(prop.name);
      }
      if (!prop.nullable && STATE_DISCRIMINANT.test(bareName)) {
        if (!(bareName === "Mode" && CONFIG_TYPE_SUFFIX.test(name))) {
          discriminantName = prop.name;
        }
      } else if (prop.nullable) {
        nullableSiblings.add(prop.name);
      }
    }

    const line = lineOf(file.content, start);
    if (lifecycleBools.size >= 2) {
      const list = [...lifecycleBools].slice(0, 5).join(", ");
      findings.push({
        id: `SM:cs-bool-soup:${file.rel}:${line}`,
        rule: "implicit-sm-boolean-soup",
        category: "structure",
        rung: "R1",
        severity: "error",
        file: file.rel,
        line,
        message: `C# ${kind} ${name} declares ${lifecycleBools.size} lifecycle bool flags (${list}) — admitting ${2 ** lifecycleBools.size} states.`,
        fix: "Replace lifecycle booleans with a closed abstract record hierarchy (discriminated union) and an explicit Transition(state, evt) method.",
      });
    }

    if (discriminantName && nullableSiblings.size >= 2) {
      const optList = [...nullableSiblings].slice(0, 5).join(", ");
      findings.push({
        id: `SM:cs-optional-bag:${file.rel}:${line}`,
        rule: "implicit-sm-optional-bag",
        category: "structure",
        rung: "R1",
        severity: "error",
        file: file.rel,
        line,
        message: `C# ${kind} ${name} pairs "${discriminantName}" with ${nullableSiblings.size} nullable payload fields (${optList}).`,
        fix: "Split into a closed abstract record hierarchy where each sealed variant carries only the non-null fields valid in that state.",
      });
    }
  }

  return findings;
}

function checkCsharpScatteredMutations(file: ScannedFile, masked: string): Finding[] {
  const methodRegex =
    /(?:^|\n)\s*(?:(?:public|private|protected|internal|static|async|virtual|override|sealed|new|partial)\s+)+(?:[A-Za-z_][A-Za-z0-9_.<>?,\s]*?\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*(?:<[^>{]*>)?\s*\([^)]*\)\s*(?:where[^{]+)?\{/g;
  const keywords = new Set(["if", "for", "foreach", "while", "switch", "catch", "lock", "using", "fixed"]);
  const typeNames = new Set<string>();
  for (const m of masked.matchAll(/\b(?:class|record|struct)\s+([A-Za-z_][A-Za-z0-9_]*)/g)) {
    if (m[1]) typeNames.add(m[1]);
  }

  const spans: Array<{ name: string; start: number; end: number }> = [];
  for (const match of masked.matchAll(methodRegex)) {
    const name = match[1] ?? "";
    if (!name || keywords.has(name) || typeNames.has(name)) continue;
    const openIdx = (match.index ?? 0) + match[0].length - 1;
    const closeIdx = findMatching(masked, openIdx, "{", "}");
    if (closeIdx < 0) continue;
    spans.push({ name, start: openIdx, end: closeIdx });
  }

  const mutationRegex = /\b(?:(?:this|[A-Za-z_][A-Za-z0-9_]*)\.)?_?(?:Status|State|Phase|Stage|status|state|phase|stage)\s*=(?!=|>)/g;
  const mutatingMethods = new Map<string, number>();

  for (const match of masked.matchAll(mutationRegex)) {
    const pos = match.index ?? 0;
    const before = masked.slice(Math.max(0, pos - 40), pos);
    if (/\b(?:new\s+[A-Za-z_]|with\s*\{|var\s+|bool\s+|string\s+|int\s+)/.test(before)) continue;
    const lineEnd = masked.indexOf("\n", pos);
    const restOfLine = masked.slice(pos, lineEnd < 0 ? pos + 120 : lineEnd);
    if (/,\s*$/.test(restOfLine) || /\bEntityState\./.test(restOfLine) || /\bAddress\.State\b/.test(restOfLine)) continue;
    const containing = spans
      .filter((s) => s.start < pos && pos < s.end)
      .sort((a, b) => a.end - a.start - (b.end - b.start))[0];
    if (!containing || CANONICAL_TRANSITION.test(containing.name)) continue;
    if (!mutatingMethods.has(containing.name)) {
      mutatingMethods.set(containing.name, lineOf(file.content, pos));
    }
  }

  if (mutatingMethods.size < 2) return [];
  const entries = [...mutatingMethods.entries()];
  const firstLine = entries[0]?.[1] ?? 1;
  const names = entries.map(([name]) => name).slice(0, 5).join(", ");
  return [
    {
      id: `SM:cs-scattered:${file.rel}:${firstLine}`,
      rule: "implicit-sm-scattered-mutation",
      category: "structure",
      rung: "R1",
      severity: "error",
      file: file.rel,
      line: firstLine,
      message: `C# state mutation scattered across ${mutatingMethods.size} methods (${names}).`,
      fix: "Centralize all state transitions inside one pure Transition(state, evt) method backed by an explicit transition table.",
    },
  ];
}

function checkCsharpSwitches(file: ScannedFile, masked: string): Finding[] {
  const findings: Finding[] = [];

  const stmtRegex = /\bswitch\s*\(\s*([^)]+?)\s*\)\s*\{/g;
  for (const match of masked.matchAll(stmtRegex)) {
    const expr = (match[1] ?? "").trim();
    if (!CS_SWITCH_TARGET.test(expr)) continue;
    const openIdx = (match.index ?? 0) + match[0].length - 1;
    const closeIdx = findMatching(masked, openIdx, "{", "}");
    if (closeIdx < 0) continue;
    const body = masked.slice(openIdx + 1, closeIdx);
    const defaultIdx = body.search(/\bdefault\s*:/);
    const hasGuard = defaultIdx >= 0 && CS_EXHAUSTIVE_THROW.test(body.slice(defaultIdx));
    if (!hasGuard) {
      const line = lineOf(file.content, match.index ?? 0);
      findings.push({
        id: `SM:cs-switch-stmt:${file.rel}:${line}`,
        rule: "implicit-sm-non-exhaustive-switch",
        category: "structure",
        rung: "R0",
        severity: "error",
        file: file.rel,
        line,
        message: `C# switch (${expr}) lacks an explicit throwing default guard.`,
        fix: "Add default: throw new UnreachableException(...) or convert to an exhaustive switch expression with _ => throw new UnreachableException(...).",
      });
    }
  }

  const exprRegex = /([A-Za-z_][A-Za-z0-9_.]*)\s+switch\s*\{/g;
  for (const match of masked.matchAll(exprRegex)) {
    const expr = (match[1] ?? "").trim();
    if (!CS_SWITCH_TARGET.test(expr)) continue;
    const openIdx = (match.index ?? 0) + match[0].length - 1;
    const closeIdx = findMatching(masked, openIdx, "{", "}");
    if (closeIdx < 0) continue;
    const body = masked.slice(openIdx + 1, closeIdx);
    const hasDiscardThrow = /(?:^|[,\n])\s*_\s*=>\s*throw\b/.test(body);
    if (!hasDiscardThrow) {
      const line = lineOf(file.content, match.index ?? 0);
      findings.push({
        id: `SM:cs-switch-expr:${file.rel}:${line}`,
        rule: "implicit-sm-non-exhaustive-switch",
        category: "structure",
        rung: "R0",
        severity: "error",
        file: file.rel,
        line,
        message: `C# switch expression on "${expr}" lacks an explicit "_ => throw ..." exhaustiveness arm.`,
        fix: "Add _ => throw new UnreachableException($\"Unhandled state: {state}\") so missing enum/record variants fail fast.",
      });
    }
  }

  return findings;
}

export function lintCsharpStateMachines(file: ScannedFile): Finding[] {
  const masked = maskCsharp(file.content);
  return [
    ...checkCsharpTypes(file, masked),
    ...checkCsharpScatteredMutations(file, masked),
    ...checkCsharpSwitches(file, masked),
  ];
}
