import { scanLexical } from "./anti-slop/lexical-mask.ts";
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

interface CommentAllowContext {
  nextCodeLine: string;
  prefixes: readonly string[];
  allowExportedTsDoc: boolean;
  language: Language;
}

function commentAllowed(hit: CommentHit, ctx: CommentAllowContext): boolean {
  const { nextCodeLine, prefixes, allowExportedTsDoc, language } = ctx;
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
  const rawHits: CommentHit[] = scanLexical(source, true, language).commentSpans;

  const isGeneratedPath = /(?:^|\/)(?:generated|generated-clients?|codegen|__snapshots__)\/|\.(?:gen|generated)\.[cm]?[jt]sx?$/i.test(file);
  const isGeneratedFile = isGeneratedPath && rawHits.some((hit) => hit.header && GENERATED.test(normalizeBody(hit.text)));
  if (isGeneratedFile) return [];

  const lines = source.split(/\r?\n/);
  const disallowed = rawHits.filter((hit) => {
    let nextIdx = hit.endLine;
    while (nextIdx < lines.length) {
      const l = lines[nextIdx] ?? "";
      if ((language === "csharp" || language === "rust") && /^\s*(?:\/\/\/|\/\/!|\[|#\[)/.test(l)) { nextIdx += 1; continue; }
      if ((language === "typescript" || language === "javascript") && /^\s*@/.test(l)) { nextIdx += 1; continue; }
      break;
    }
    const nextCodeLine = lines[nextIdx] ?? "";
    return !commentAllowed(hit, { nextCodeLine, prefixes, allowExportedTsDoc, language });
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
