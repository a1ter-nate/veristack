import type { Finding, Language } from "./types.ts";

export interface CommentHit {
  line: number;
  endLine: number;
  kind: "line" | "block";
  text: string;
  header: boolean;
}

export interface NoCommentsOptions {
  allowPrefixes?: readonly string[];
  allowExportedTsDoc?: boolean;
}

const DIRECTIVE =
  /^(?:eslint-(?:disable|enable)|oxlint-(?:disable|enable)|oxc-|prettier-ignore|biome-ignore|istanbul\s+ignore|c8\s+ignore|v8\s+ignore|node:coverage|@ts-(?:expect-error|ignore|nocheck|check)|ts-(?:expect-error|ignore|nocheck|check)|@?vitest-environment\b|@jsx(?:ImportSource|Frag|Runtime)?\b|<reference\b|nosonar|codeql|fmt:(?:off|on)|@__PURE__|@__NO_SIDE_EFFECTS__|type:\s*ignore|noqa\b|pragma:\s*no\s*cover|pylint:|mypy:|pyright:|go:generate|go:embed|go:build|\+build\b|nolint:|clippy::|rustfmt::)/i;

const LEGAL =
  /\b(?:spdx-license-identifier:|copyright\b|licensed under\b|@license\b|all rights reserved\b)/i;

const GENERATED =
  /<(?:auto-)?generated\b|auto-generated|generated code|\bdo not (?:manually )?edit\b/i;

function normalizeBody(raw: string): string {
  return raw
    .replace(/^\s*\*+\s?/gm, "")
    .replace(/^\s*\/+/gm, "")
    .replace(/^\s*#+\s?/gm, "")
    .trim();
}

function hasAllowedPrefix(inner: string, prefixes: readonly string[]): boolean {
  const upper = inner.toUpperCase();
  return prefixes.some((prefix) => {
    const clean = prefix.trim().toUpperCase();
    return clean.length > 0 && upper.startsWith(`${clean}:`);
  });
}

function commentAllowed(
  hit: CommentHit,
  nextCodeLine: string,
  prefixes: readonly string[],
  allowExportedTsDoc: boolean,
  language: Language,
): boolean {
  const inner = normalizeBody(hit.text);
  if (!inner) return true;
  if (GENERATED.test(inner)) return true;
  if (DIRECTIVE.test(inner)) return true;
  if (hit.header && LEGAL.test(inner)) return true;
  if (hasAllowedPrefix(inner, prefixes)) return true;
  if (allowExportedTsDoc && hit.kind === "block" && hit.text.startsWith("*") && /^\s*export\b/.test(nextCodeLine)) {
    return true;
  }
  if (
    allowExportedTsDoc &&
    language === "csharp" &&
    hit.kind === "line" &&
    hit.text.startsWith("/") &&
    /^\s*(?:\[.*\]\s*)*public\b/.test(nextCodeLine)
  ) {
    return true;
  }
  if (
    allowExportedTsDoc &&
    language === "rust" &&
    hit.kind === "line" &&
    (hit.text.startsWith("!") || (hit.text.startsWith("/") && /^\s*(?:#\[.*\]\s*)*pub\b/.test(nextCodeLine)))
  ) {
    return true;
  }
  return false;
}

const REGEX_PREV_KEYWORDS = new Set([
  "return",
  "case",
  "throw",
  "in",
  "of",
  "typeof",
  "void",
  "delete",
  "yield",
  "await",
  "new",
  "else",
  "do",
]);

function canStartRegex(prevNonSpace: string, prevWord: string): boolean {
  if (!prevNonSpace) return true;
  if ("([{:;,=!?&|^~+-*%<>".includes(prevNonSpace)) return true;
  return REGEX_PREV_KEYWORDS.has(prevWord);
}

function findSlashComments(source: string, language: Language): CommentHit[] {
  const hits: CommentHit[] = [];
  let i = 0;
  let line = 1;
  let seenCode = false;
  let atBol = true;
  let prevNonSpace = "";
  let prevWord = "";

  const bump = (n = 1): void => {
    for (let k = 0; k < n && i < source.length; k++) {
      if (source[i] === "\n") line += 1;
      i += 1;
    }
  };

  const skipQuoted = (quote: string, verbatim: boolean): void => {
    bump(1);
    while (i < source.length) {
      const ch = source[i];
      if (verbatim && ch === quote && source[i + 1] === quote) {
        bump(2);
        continue;
      }
      if (!verbatim && ch === "\\") {
        bump(2);
        continue;
      }
      if (ch === quote) {
        bump(1);
        return;
      }
      bump(1);
    }
  };

  const skipRegexLiteral = (): void => {
    bump(1);
    let inClass = false;
    while (i < source.length && source[i] !== "\n") {
      const ch = source[i];
      if (ch === "\\") {
        bump(2);
        continue;
      }
      if (ch === "[") {
        inClass = true;
        bump(1);
        continue;
      }
      if (ch === "]") {
        inClass = false;
        bump(1);
        continue;
      }
      if (ch === "/" && !inClass) {
        bump(1);
        while (i < source.length && /[a-z]/i.test(source[i] ?? "")) bump(1);
        return;
      }
      bump(1);
    }
  };

  if (source.startsWith("#!")) {
    while (i < source.length && source[i] !== "\n") i += 1;
  }

  const supportsRegex = language === "typescript" || language === "javascript";

  while (i < source.length) {
    const a = source[i] ?? "";
    const b = source[i + 1] ?? "";

    if (a === "\n") {
      atBol = true;
      bump(1);
      continue;
    }
    if (/\s/.test(a)) {
      bump(1);
      continue;
    }
    if (language === "csharp" && atBol && a === "#") {
      seenCode = true;
      while (i < source.length && source[i] !== "\n") i += 1;
      continue;
    }
    if (a === "/" && b === "/") {
      const startLine = line;
      bump(2);
      const start = i;
      while (i < source.length && source[i] !== "\n") i += 1;
      hits.push({ line: startLine, endLine: startLine, kind: "line", text: source.slice(start, i), header: !seenCode });
      continue;
    }
    if (a === "/" && b === "*") {
      const startLine = line;
      bump(2);
      const start = i;
      while (i < source.length && !(source[i] === "*" && source[i + 1] === "/")) bump(1);
      hits.push({ line: startLine, endLine: line, kind: "block", text: source.slice(start, i), header: !seenCode });
      if (i < source.length) bump(2);
      continue;
    }

    seenCode = true;
    atBol = false;

    if (supportsRegex && a === "/" && canStartRegex(prevNonSpace, prevWord)) {
      skipRegexLiteral();
      prevNonSpace = "/";
      prevWord = "";
      continue;
    }

    if (language === "csharp" && a === "$") {
      let dollars = 0; while (source[i + dollars] === "$") dollars += 1;
      let qCount = 0; while (source[i + dollars + qCount] === '"') qCount += 1;
      if (qCount >= 3) {
        bump(dollars + qCount);
        while (i < source.length) {
          if (source[i] === '"') {
            let closeQ = 0; while (source[i + closeQ] === '"') closeQ += 1;
            if (closeQ >= qCount) { bump(closeQ); break; }
            bump(closeQ); continue;
          }
          bump(1);
        }
        prevNonSpace = '"'; prevWord = ""; continue;
      }
    }
    if (language === "csharp" && a === '"' && b === '"' && source[i + 2] === '"') {
      let qCount = 3; while (source[i + qCount] === '"') qCount += 1;
      bump(qCount);
      while (i < source.length) {
        if (source[i] === '"') {
          let closeQ = 0; while (source[i + closeQ] === '"') closeQ += 1;
          if (closeQ >= qCount) { bump(closeQ); break; }
          bump(closeQ); continue;
        }
        bump(1);
      }
      prevNonSpace = '"'; prevWord = ""; continue;
    }
    if (language === "csharp" && ((a === "@" && b === '"') || (((a === "@" && b === "$") || (a === "$" && b === "@")) && source[i + 2] === '"'))) {
      bump(a === "@" && b === '"' ? 1 : 2);
      skipQuoted('"', true);
      prevNonSpace = '"';
      prevWord = "";
      continue;
    }
    if (language === "rust" && (a === "r" || (a === "b" && b === "r")) && (i === 0 || !/[A-Za-z0-9_]/.test(source[i - 1] ?? ""))) {
      const pLen = a === "b" ? 2 : 1;
      let hashes = 0;
      while (source[i + pLen + hashes] === "#") hashes += 1;
      if (source[i + pLen + hashes] === '"') {
        bump(pLen + hashes + 1);
        while (i < source.length) {
          if (source[i] === '"') {
            let h = 0;
            while (h < hashes && source[i + 1 + h] === "#") h += 1;
            if (h === hashes) { bump(1 + hashes); break; }
          }
          bump(1);
        }
        prevNonSpace = '"';
        prevWord = "";
        continue;
      }
    }
    if (language === "rust" && a === "'" && /[a-zA-Z_]/.test(b) && source[i + 2] !== "'") {
      bump(1);
      prevNonSpace = "'";
      prevWord = "";
      continue;
    }
    if (a === '"' || a === "'" || (a === "`" && language !== "rust")) {
      const verbatim = a === "`" && language === "go";
      skipQuoted(a, verbatim);
      prevNonSpace = a;
      prevWord = "";
      continue;
    }

    if (/[A-Za-z_$]/.test(a)) {
      const wordStart = i;
      while (i < source.length && /[A-Za-z0-9_$]/.test(source[i] ?? "")) bump(1);
      prevWord = source.slice(wordStart, i);
      prevNonSpace = prevWord[prevWord.length - 1] ?? "";
      continue;
    }

    prevNonSpace = a;
    prevWord = "";
    bump(1);
  }

  return hits;
}

function findHashComments(source: string): CommentHit[] {
  const hits: CommentHit[] = [];
  let i = 0;
  let line = 1;
  let seenCode = false;

  const bump = (n = 1): void => {
    for (let k = 0; k < n && i < source.length; k++) {
      if (source[i] === "\n") line += 1;
      i += 1;
    }
  };

  if (source.startsWith("#!")) {
    while (i < source.length && source[i] !== "\n") i += 1;
  }

  while (i < source.length) {
    const a = source[i] ?? "";
    if (/\s/.test(a)) {
      bump(1);
      continue;
    }
    if (a === "#") {
      const startLine = line;
      bump(1);
      const start = i;
      while (i < source.length && source[i] !== "\n") i += 1;
      hits.push({ line: startLine, endLine: startLine, kind: "line", text: source.slice(start, i), header: !seenCode });
      continue;
    }

    seenCode = true;

    if (a === '"' || a === "'") {
      const triple = source[i + 1] === a && source[i + 2] === a;
      if (triple) {
        bump(3);
        while (i < source.length) {
          if (source[i] === "\\") {
            bump(2);
            continue;
          }
          if (source[i] === a && source[i + 1] === a && source[i + 2] === a) {
            bump(3);
            break;
          }
          bump(1);
        }
        continue;
      }
      bump(1);
      while (i < source.length && source[i] !== "\n") {
        if (source[i] === "\\") {
          bump(2);
          continue;
        }
        if (source[i] === a) {
          bump(1);
          break;
        }
        bump(1);
      }
      continue;
    }
    bump(1);
  }

  return hits;
}

function groupContiguous(hits: readonly CommentHit[]): CommentHit[] {
  const out: CommentHit[] = [];
  for (const hit of hits) {
    const prev = out[out.length - 1];
    if (prev && hit.line <= prev.endLine + 1 && prev.kind === hit.kind) {
      prev.endLine = Math.max(prev.endLine, hit.endLine);
      prev.text = `${prev.text}\n${hit.text}`;
      continue;
    }
    out.push({ ...hit });
  }
  return out;
}

export function lintNoComments(
  file: string,
  source: string,
  language: Language,
  options: NoCommentsOptions = {},
): Finding[] {
  const prefixes = options.allowPrefixes ?? ["WARNING", "SAFETY"];
  const allowExportedTsDoc = options.allowExportedTsDoc ?? true;
  const rawHits = language === "python" ? findHashComments(source) : findSlashComments(source, language);

  const isGeneratedPath = /(?:^|\/)(?:generated|generated-clients?|codegen|__snapshots__)\/|\.(?:gen|generated)\.[cm]?[jt]sx?$/i.test(file);
  const isGeneratedFile = isGeneratedPath && rawHits.some((hit) => hit.header && GENERATED.test(normalizeBody(hit.text)));
  if (isGeneratedFile) return [];

  const lines = source.split(/\r?\n/);
  const disallowed = rawHits.filter((hit) => {
    let nextIdx = hit.endLine;
    while (
      (language === "csharp" || language === "rust") &&
      nextIdx < lines.length &&
      /^\s*(?:\/\/\/|\/\/!|\[|#\[)/.test(lines[nextIdx] ?? "")
    ) {
      nextIdx += 1;
    }
    const nextCodeLine = lines[nextIdx] ?? "";
    return !commentAllowed(hit, nextCodeLine, prefixes, allowExportedTsDoc, language);
  });

  const grouped = groupContiguous(disallowed);
  const allowedTagHint = prefixes.map((p) => `${p.toUpperCase()}:`).join(" or ");

  return grouped.map((hit) => ({
    id: `NC:${file}:${hit.line}`,
    rule: "no-comments",
    category: "no-comments",
    rung: "R0",
    severity: "error",
    file,
    line: hit.line,
    message: `Prose comment at line ${hit.line}${hit.endLine > hit.line ? `-${hit.endLine}` : ""}.`,
    fix: `Delete tautology/excuse comment, express intent in names/types, move rationale to an ADR, or prefix genuine footguns with ${allowedTagHint}.`,
  }));
}
