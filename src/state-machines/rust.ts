import type { ScannedFile } from "../discover.ts";
import type { Finding } from "../types.ts";

const LIFECYCLE_BOOL_NAME =
  /^(?:is(?:Running|Armed|Stopped|Draining|Loading|Error|Errored|Pending|Complete|Completed|Closed|Cancelled|Canceled|Connected|Disconnected|Paused|Ready|Open|Opened|Idle|Active|Busy|Starting|Stopping|Retrying|Failed|Succeeded|Aborted|Expired|Reverted|Locked|Unlocked|Initialized|Disposed|Healthy|Degraded)|has(?:Started|Failed|Finished|Completed|Closed|Cancelled|Canceled|Errored|Connected|TimedOut|Expired|Reverted|Stopped|Succeeded)|was(?:Reverted|Cancelled|Canceled|Stopped|Closed|Aborted|Failed|Started)|aborted|armed|draining|saturated|stopping|starting|reverted|expired|active|running|stopped|loading|pending|closed|cancelled|canceled|connected|paused|completed|failed|disposed)$/i;

const STATE_DISCRIMINANT = /^(?:status|state|phase|stage|mode)$/;
const CONFIG_TYPE_SUFFIX = /(?:Options|Config|Configuration|Settings|Flags|Args|Params|Props|Input|Query|Filter)$/;
const WIRE_OR_ROW_TYPE_NAME =
  /(?:Row|Dto|Request|Response|Report|Summary|Diagnostic|Record|Entry|Patch|Form|Save|Params|Args|Config|Configuration|Options|Settings|Flags|Input|Query|Filter|Payload)$|^(?:Row|Stored|New|Create|Update|Start|Prepared)[A-Z]/;
const WIRE_ATTR_MARKER = /\b(?:Deserialize|Serialize|FromRow|Parser|Args)\b|#\[(?:serde|sqlx|clap)\(/;
const CANONICAL_TRANSITION = /^(?:transition|reduce|apply_event|next_state|step|step_state|handle_event|new|default)$/i;
const RUST_MATCH_TARGET = /^(?:(?:self\.)?[a-zA-Z_][a-zA-Z0-9_.]*\.)?(?:status|state|phase|stage|kind)$/;

function lineOf(text: string, index: number): number {
  let line = 1;
  for (let i = 0; i < index; i++) {
    if (text[i] === "\n") line += 1;
  }
  return line;
}

function toCamel(snake: string): string {
  return snake.replace(/^_+/, "").replace(/_([a-zA-Z0-9])/g, (_, ch: string) => ch.toUpperCase());
}

function maskRust(source: string): string {
  const out = source.split("");
  let inString = false;
  let escaped = false;
  let lineComment = false;
  let blockDepth = 0;

  for (let i = 0; i < source.length; i++) {
    const ch = source[i] ?? "";
    const next = source[i + 1] ?? "";
    if (lineComment) {
      if (ch === "\n") lineComment = false;
      else out[i] = " ";
      continue;
    }
    if (blockDepth > 0) {
      if (ch === "/" && next === "*") {
        out[i] = " ";
        out[i + 1] = " ";
        blockDepth += 1;
        i += 1;
      } else if (ch === "*" && next === "/") {
        out[i] = " ";
        out[i + 1] = " ";
        blockDepth -= 1;
        i += 1;
      } else if (ch !== "\n") {
        out[i] = " ";
      }
      continue;
    }
    if (inString) {
      if (ch !== "\n" && ch !== "\r") out[i] = " ";
      if (escaped) {
        escaped = false;
        continue;
      }
      if (ch === "\\") {
        escaped = true;
        continue;
      }
      if (ch === '"') inString = false;
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
      blockDepth = 1;
      i += 1;
      continue;
    }
    if (ch === '"') {
      inString = true;
      out[i] = " ";
    }
  }
  return out.join("");
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

function stripTestModules(masked: string): string {
  const out = masked.split("");
  const cfgTest = /#\[cfg\(test\)\]\s*(?:pub\s+)?mod\s+[A-Za-z_][A-Za-z0-9_]*\s*\{/g;
  for (const match of masked.matchAll(cfgTest)) {
    const openIdx = (match.index ?? 0) + match[0].length - 1;
    const closeIdx = findMatchingBrace(masked, openIdx);
    if (closeIdx < 0) continue;
    for (let i = match.index ?? 0; i <= closeIdx; i++) {
      if (out[i] !== "\n") out[i] = " ";
    }
  }
  return out.join("");
}

function findHeaderOpenBrace(masked: string, fromIdx: number, stopOnParenAtZero: boolean): number {
  let parenDepth = 0;
  let angleDepth = 0;
  const limit = Math.min(masked.length, fromIdx + 2000);
  for (let i = fromIdx; i < limit; i++) {
    const ch = masked[i];
    if (ch === "(") {
      if (stopOnParenAtZero && angleDepth === 0 && parenDepth === 0) return -1;
      parenDepth += 1;
    } else if (ch === ")") {
      parenDepth = Math.max(0, parenDepth - 1);
    } else if (ch === "<") {
      angleDepth += 1;
    } else if (ch === ">" && masked[i - 1] !== "-") {
      angleDepth = Math.max(0, angleDepth - 1);
    } else if (parenDepth === 0 && angleDepth === 0) {
      if (ch === ";") return -1;
      if (ch === "{") return i;
    }
  }
  return -1;
}

function checkRustStructs(file: ScannedFile, prodMasked: string): Finding[] {
  const findings: Finding[] = [];
  const structRegex = /\bstruct\s+([A-Za-z_][A-Za-z0-9_]*)\b/g;

  for (const match of prodMasked.matchAll(structRegex)) {
    const name = match[1] ?? "";
    const start = match.index ?? 0;
    const openIdx = findHeaderOpenBrace(prodMasked, start + match[0].length, true);
    if (openIdx < 0) continue;
    const closeIdx = findMatchingBrace(prodMasked, openIdx);
    if (closeIdx < 0) continue;

    const body = prodMasked.slice(openIdx + 1, closeIdx);
    const fields = body.split(",").map((s) => s.trim()).filter(Boolean);
    const lifecycleBools = new Set<string>();
    let discriminantName = "";
    const optionSiblings = new Set<string>();

    for (const rawField of fields) {
      const cleaned = rawField.replace(/(?:#\[[^\]]*\]\s*)+/g, "").trim();
      const fieldMatch = /^(?:pub(?:\([^)]*\))?\s+)?([a-zA-Z_][a-zA-Z0-9_]*)\s*:\s*([\s\S]+)$/.exec(cleaned);
      if (!fieldMatch) continue;
      const fieldName = fieldMatch[1] ?? "";
      const fieldType = (fieldMatch[2] ?? "").trim();

      if (fieldType === "bool" && LIFECYCLE_BOOL_NAME.test(toCamel(fieldName))) {
        lifecycleBools.add(fieldName);
      }

      const isOption = /^(?:(?:std|core)::option::)?Option\s*</.test(fieldType);
      if (!isOption && STATE_DISCRIMINANT.test(fieldName)) {
        if (!(fieldName === "mode" && CONFIG_TYPE_SUFFIX.test(name))) {
          discriminantName = fieldName;
        }
      } else if (isOption) {
        optionSiblings.add(fieldName);
      }
    }

    const line = lineOf(file.content, start);
    if (lifecycleBools.size >= 2) {
      const list = [...lifecycleBools].slice(0, 5).join(", ");
      findings.push({
        id: `SM:rs-bool-soup:${file.rel}:${line}`,
        rule: "implicit-sm-boolean-soup",
        category: "structure",
        rung: "R1",
        severity: "error",
        file: file.rel,
        line,
        message: `Rust struct ${name} declares ${lifecycleBools.size} lifecycle bool fields (${list}) — admitting ${2 ** lifecycleBools.size} states.`,
        fix: "Replace lifecycle booleans with a Rust enum where each variant owns its state data and transitions live in one transition() function.",
      });
    }

    const rawBody = file.content.slice(openIdx + 1, closeIdx);
    const attrWindow = file.content.slice(Math.max(0, start - 360), start);
    const lastDelimiter = Math.max(attrWindow.lastIndexOf("}"), attrWindow.lastIndexOf(";"));
    const headerAttrs = lastDelimiter >= 0 ? attrWindow.slice(lastDelimiter + 1) : attrWindow;
    const isWireOrRowStruct =
      WIRE_OR_ROW_TYPE_NAME.test(name) ||
      WIRE_ATTR_MARKER.test(headerAttrs) ||
      /#\[(?:serde|sqlx|clap)\(/.test(rawBody);

    if (discriminantName && optionSiblings.size >= 2 && !isWireOrRowStruct) {
      const optList = [...optionSiblings].slice(0, 5).join(", ");
      findings.push({
        id: `SM:rs-optional-bag:${file.rel}:${line}`,
        rule: "implicit-sm-optional-bag",
        category: "structure",
        rung: "R1",
        severity: "error",
        file: file.rel,
        line,
        message: `Rust struct ${name} pairs "${discriminantName}" with ${optionSiblings.size} Option<T> payload fields (${optList}).`,
        fix: "Split into a Rust enum where each variant holds only the non-Option fields valid in that state.",
      });
    }
  }

  return findings;
}

function checkRustScatteredMutations(file: ScannedFile, prodMasked: string): Finding[] {
  const fnRegex = /\bfn\s+([a-zA-Z_][a-zA-Z0-9_]*)\b/g;
  const spans: Array<{ name: string; start: number; end: number }> = [];

  for (const match of prodMasked.matchAll(fnRegex)) {
    const name = match[1] ?? "";
    const openIdx = findHeaderOpenBrace(prodMasked, (match.index ?? 0) + match[0].length, false);
    if (openIdx < 0) continue;
    const closeIdx = findMatchingBrace(prodMasked, openIdx);
    if (closeIdx < 0) continue;
    spans.push({ name, start: openIdx, end: closeIdx });
  }

  const mutationRegex = /\b(?:self|[a-zA-Z_][a-zA-Z0-9_]*)\.(?:status|state|phase|stage)\s*=(?!=|>)/g;
  const mutatingFns = new Map<string, number>();

  for (const match of prodMasked.matchAll(mutationRegex)) {
    const pos = match.index ?? 0;
    const containing = spans
      .filter((s) => s.start < pos && pos < s.end)
      .sort((a, b) => a.end - a.start - (b.end - b.start))[0];
    if (!containing || CANONICAL_TRANSITION.test(containing.name)) continue;
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
      id: `SM:rs-scattered:${file.rel}:${firstLine}`,
      rule: "implicit-sm-scattered-mutation",
      category: "structure",
      rung: "R1",
      severity: "error",
      file: file.rel,
      line: firstLine,
      message: `Rust state mutation scattered across ${mutatingFns.size} functions (${names}).`,
      fix: "Centralize transitions in one pure transition(state, event) function backed by an exhaustive enum match.",
    },
  ];
}

const NON_DOMAIN_ENUM_PREFIX = /^(?:StatusCode|KeyCode|ErrorKind|EventKind|TokenKind|SyntaxKind|Tag|HttpStatus)::/;

function checkRustWildcardStateMatches(file: ScannedFile, prodMasked: string): Finding[] {
  const findings: Finding[] = [];
  const seenLines = new Set<number>();
  const matchRegex = /\bmatch\s+([a-zA-Z_][a-zA-Z0-9_.]*)\s*\{/g;

  for (const match of prodMasked.matchAll(matchRegex)) {
    const expr = (match[1] ?? "").trim();
    if (!RUST_MATCH_TARGET.test(expr)) continue;
    const openIdx = (match.index ?? 0) + match[0].length - 1;
    const closeIdx = findMatchingBrace(prodMasked, openIdx);
    if (closeIdx < 0) continue;

    const body = prodMasked.slice(openIdx + 1, closeIdx);
    let hasDomainEnumPattern = false;
    let hasSilentWildcard = false;
    let depth = 0;
    let armStart = 0;

    for (let i = 0; i < body.length; i++) {
      const ch = body[i];
      if (ch === "{" || ch === "(" || ch === "[") {
        depth += 1;
      } else if (ch === "}" || ch === ")" || ch === "]") {
        depth = Math.max(0, depth - 1);
      } else if (depth === 0 && ch === "=" && body[i + 1] === ">") {
        const pattern = body.slice(armStart, i).replace(/^[\s,]+/, "").trim();
        const rhsTail = body.slice(i + 2, i + 40).trim();
        if (pattern === "_" && !/^(?:unreachable!|panic!)/.test(rhsTail)) {
          hasSilentWildcard = true;
        }
        const enumMatch = /\b([A-Z][A-Za-z0-9_]*::[A-Z][A-Za-z0-9_]*)\b/.exec(pattern);
        if (enumMatch && !NON_DOMAIN_ENUM_PREFIX.test(enumMatch[1] ?? "")) {
          hasDomainEnumPattern = true;
        }
        i += 1;
      } else if (depth === 0 && (ch === "," || ch === "\n")) {
        if (ch === ",") armStart = i + 1;
      }
    }

    if (!hasDomainEnumPattern || !hasSilentWildcard) continue;

    const line = lineOf(file.content, match.index ?? 0);
    if (seenLines.has(line)) continue;
    seenLines.add(line);
    findings.push({
      id: `SM:rs-wildcard-match:${file.rel}:${line}`,
      rule: "implicit-sm-non-exhaustive-switch",
      category: "structure",
      rung: "R0",
      severity: "error",
      file: file.rel,
      line,
      message: `Rust match ${expr} uses a silent wildcard arm (_ => ...) that hides future state variants.`,
      fix: "List every enum state variant explicitly (and enable clippy::wildcard_enum_match_arm = \"deny\") so adding a state is a compile error.",
    });
  }

  return findings;
}

export function lintRustStateMachines(file: ScannedFile): Finding[] {
  const masked = maskRust(file.content);
  const prodMasked = stripTestModules(masked);
  return [
    ...checkRustStructs(file, prodMasked),
    ...checkRustScatteredMutations(file, prodMasked),
    ...checkRustWildcardStateMatches(file, prodMasked),
  ];
}
