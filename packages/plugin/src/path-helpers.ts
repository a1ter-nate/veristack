import path from "node:path";
import type { Language } from "./types.ts";

export function detectLanguage(rel: string): Language | undefined {
  const lower = rel.toLowerCase();
  if (lower.endsWith(".ts") || lower.endsWith(".tsx") || lower.endsWith(".mts") || lower.endsWith(".cts")) return "typescript";
  if (lower.endsWith(".js") || lower.endsWith(".jsx") || lower.endsWith(".mjs") || lower.endsWith(".cjs")) return "javascript";
  if (lower.endsWith(".cs") || lower.endsWith(".csx")) return "csharp";
  if (lower.endsWith(".py") || lower.endsWith(".pyi")) return "python";
  if (lower.endsWith(".rs")) return "rust";
  if (lower.endsWith(".go")) return "go";
  return undefined;
}

export function isDeclarationStub(rel: string): boolean {
  return /\.(?:d\.[cm]?ts|pyi)$/i.test(rel);
}

export function isTestFilePath(rel: string, hasLanguage?: boolean): boolean {
  const norm = rel.replace(/\\/g, "/");
  const lower = norm.toLowerCase();
  const base = path.posix.basename(lower);
  if (/\.(?:test|spec|e2e|cy|int|integration|contract)\.[cm]?[jt]sx?$/.test(base)) return true;
  if (/(?:^|[-_.])tests?\.py$|^test[-_.].*\.py$|^conftest\.py$/.test(base)) return true;
  if (/_test\.go$|(?:^|[-_])tests?\.rs$|^test[-_].*\.rs$/.test(base)) return true;
  if (/tests?\.cs$|specs?\.cs$/.test(base)) return true;
  if (/(?:^|\/)[^/]+\.(?:tests?|unittests|integrationtests|specs?)\//.test(lower) && lower.endsWith(".cs")) return true;
  if (/(?:^|[-_])tests?\.(?:sh|bash)$/.test(base) || (/^(?:tests?|__tests__)\//.test(lower) && /\.(?:sh|bash)$/.test(base))) return true;
  if (/^(?:tests?|__tests__|specs?|e2e)\//.test(lower) || /\/(?:tests?|__tests__|specs?|e2e)\//.test(lower)) {
    if (/(?:^|\.)config\.[cm]?[jt]sx?$/.test(base)) return false;
    if (/\/(?:contracts|fixtures|helpers|support|mocks|stubs)\//.test(lower)) return false;
    if (hasLanguage !== undefined) return hasLanguage;
    return detectLanguage(rel) !== undefined;
  }
  return false;
}

export function globMatchesPath(pattern: string, relPath: string): boolean {
  const normPath = relPath.replace(/\\/g, "/").replace(/^\/+/, "");
  const raw = pattern.trim().replace(/\\/g, "/");
  if (!raw || raw.startsWith("!")) return false;
  const anchored = raw.startsWith("/");
  const isDir = raw.endsWith("/");
  const body = raw.replace(/^\/+/, "").replace(/\/+$/, "");
  if (!body) return true;
  const hasSlash = body.includes("/");
  const escaped = body
    .replace(/[.+^${}()|[\]\\]/g, "\\$&")
    .replace(/\*\*/g, "__DBLSTAR__")
    .replace(/\*/g, "[^/]*")
    .replace(/\?/g, "[^/]")
    .replace(/__DBLSTAR__/g, ".*");
  const prefix = anchored || hasSlash ? "^" : "(?:^|/)";
  const suffix = isDir ? "(?:/|$)" : "(?:/.*|$)";
  return new RegExp(`${prefix}${escaped}${suffix}`).test(normPath);
}

export const pathHelpers = Object.freeze({
  detectLanguage,
  isDeclarationStub,
  isTestFilePath,
  globMatchesPath,
});
