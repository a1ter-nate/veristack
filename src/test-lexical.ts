import path from "node:path";
import type { DiscoveredRepo } from "./discover.ts";
import type { Finding } from "./types.ts";

const IMPORT_SOURCE = /^\s*import\s+(?!type\b)[\s\S]*?\bfrom\s*["']([^"']+)["']/gm;
const FRAMEWORK_IMPORT =
  /^(?:vitest|@vitest\/|@testing-library\/|node:|bun:test$|msw(?:\/|$)|@jest\/globals$|jest$|chai$|nock$|@playwright\/test$|fast-check$)/;
const CSHARP_USING = /^\s*using\s+(?:static\s+)?([A-Za-z_][A-Za-z0-9_.]*)\s*;/gm;
const CSHARP_FRAMEWORK_USING =
  /^(?:System(?:\.|$)|Xunit(?:\.|$)|NUnit(?:\.|$)|Microsoft\.VisualStudio\.TestTools|FsCheck(?:\.|$)|Moq(?:\.|$)|NSubstitute(?:\.|$)|FluentAssertions(?:\.|$))/;
const RUST_USE = /^\s*use\s+([A-Za-z_][A-Za-z0-9_]*)::/gm;
const RUST_FRAMEWORK_USE = /^(?:std|core|alloc|proptest|rstest|tokio|serde|serde_json|wiremock|mockito|mockall|stateright)$/;
const PY_IMPORT = /^\s*(?:from\s+([A-Za-z_][A-Za-z0-9_.]*)\s+import|import\s+([A-Za-z_][A-Za-z0-9_.]*))/gm;
const PY_FRAMEWORK_IMPORT =
  /^(?:pytest|unittest|hypothesis|mock|respx|httpx|json|os|sys|re|math|time|datetime|pathlib|collections|dataclasses|typing|random|functools|itertools|tempfile|subprocess|asyncio|inspect)$/;
const CSHARP_PARENT_NS_TEST = /^\s*namespace\s+[A-Za-z_][A-Za-z0-9_.]*\.(?:Tests?|Specs?)\b/m;
const CSHARP_FRAMEWORK_TYPE =
  /^(?:Assert|Fact|Theory|Task|DateTime|DateTimeOffset|TimeSpan|Random|Thread|Environment|JsonSerializer|File|Path|Guid|Console|Math|String|Enumerable|List|Dictionary|HashSet|Array|Object|Exception|InvalidOperationException|ArgumentException|StringComparison|CancellationToken|HttpStatusCode|Stopwatch|Mock|Substitute)$/;

const VITEST_CONFIG_FILE = /^(?:vitest|vite)\.config\.[cm]?[jt]s$/i;
const PINS_UTC = /\benv\s*:\s*\{[^}]*\bTZ\s*:\s*["']UTC["']/;
const MOCK_RESTORATION_CHECKS = [
  { key: "restoreMocks", regex: /\brestoreMocks\s*:\s*true\b/ },
  { key: "unstubGlobals", regex: /\bunstubGlobals\s*:\s*true\b/ },
  { key: "unstubEnvs", regex: /\bunstubEnvs\s*:\s*true\b/ },
] as const;

export function maskStrings(text: string): string {
  const out = [...text];
  let quote = "";
  let tripleQuote = "";
  let tripleLen = 0;
  let verbatimCSharp = false;
  let rustRawHashes = -1;
  let escaped = false;
  for (let i = 0; i < text.length; i++) {
    const ch = text[i] ?? "";
    if (tripleQuote) {
      if (ch !== "\n" && ch !== "\r") out[i] = " ";
      if (ch === tripleQuote) {
        let count = 0;
        while (i + count < text.length && text[i + count] === tripleQuote) count += 1;
        if (count >= tripleLen) {
          for (let k = 0; k < count; k++) out[i + k] = " ";
          i += count - 1;
          tripleQuote = "";
          tripleLen = 0;
        }
      }
      continue;
    }
    if (verbatimCSharp) {
      if (ch !== "\n" && ch !== "\r") out[i] = " ";
      if (ch === '"') {
        if (text[i + 1] === '"') {
          out[i + 1] = " ";
          i += 1;
        } else {
          verbatimCSharp = false;
        }
      }
      continue;
    }
    if (rustRawHashes >= 0) {
      if (ch !== "\n" && ch !== "\r") out[i] = " ";
      if (ch === '"') {
        let hashes = 0;
        while (hashes < rustRawHashes && text[i + 1 + hashes] === "#") hashes += 1;
        if (hashes === rustRawHashes) {
          for (let k = 1; k <= hashes; k++) out[i + k] = " ";
          i += hashes;
          rustRawHashes = -1;
        }
      }
      continue;
    }
    if (!quote) {
      if (ch === "@" && text[i + 1] === '"') {
        out[i] = " ";
        out[i + 1] = " ";
        i += 1;
        verbatimCSharp = true;
        continue;
      }
      if (ch === "r" && (i === 0 || !/[A-Za-z0-9_]/.test(text[i - 1] ?? ""))) {
        let hashes = 0;
        while (text[i + 1 + hashes] === "#") hashes += 1;
        if (text[i + 1 + hashes] === '"') {
          for (let k = 0; k <= hashes + 1; k++) out[i + k] = " ";
          i += hashes + 1;
          rustRawHashes = hashes;
          continue;
        }
      }
      if ((ch === '"' || ch === "'") && text[i + 1] === ch && text[i + 2] === ch) {
        let count = 3;
        while (text[i + count] === ch) count += 1;
        for (let k = 0; k < count; k++) out[i + k] = " ";
        i += count - 1;
        tripleQuote = ch;
        tripleLen = count;
        continue;
      }
      if (ch === '"' || ch === "'" || ch === "`") {
        quote = ch;
        out[i] = " ";
      }
      continue;
    }
    if (ch === "\n" || ch === "\r") {
      escaped = false;
      if (quote !== "`") quote = "";
      continue;
    }
    out[i] = " ";
    if (escaped) {
      escaped = false;
      continue;
    }
    if (ch === "\\") {
      escaped = true;
      continue;
    }
    if (ch === quote) quote = "";
  }
  return out.join("");
}

export function lineOf(content: string, index: number): number {
  let line = 1;
  for (let i = 0; i < index; i++) {
    if (content[i] === "\n") line += 1;
  }
  return line;
}

export function hasNonFrameworkImport(raw: string, language?: string): boolean {
  if (language === "csharp") {
    for (const match of raw.matchAll(CSHARP_USING)) {
      const ns = match[1] ?? "";
      if (!CSHARP_FRAMEWORK_USING.test(ns)) return true;
    }
    if (CSHARP_PARENT_NS_TEST.test(raw)) {
      const masked = maskStrings(raw);
      for (const match of masked.matchAll(/\bnew\s+([A-Z][A-Za-z0-9_]*)\s*[<(]/g)) {
        const typeName = match[1] ?? "";
        if (!CSHARP_FRAMEWORK_TYPE.test(typeName)) return true;
      }
    }
    return false;
  }
  if (language === "rust") {
    for (const match of raw.matchAll(RUST_USE)) {
      const root = match[1] ?? "";
      if (!RUST_FRAMEWORK_USE.test(root)) return true;
    }
    return /\bsuper::|\bcrate::/.test(raw);
  }
  if (language === "python") {
    for (const match of raw.matchAll(PY_IMPORT)) {
      const mod = (match[1] ?? match[2] ?? "").split(".")[0] ?? "";
      if (mod && !PY_FRAMEWORK_IMPORT.test(mod)) return true;
    }
    return false;
  }
  for (const match of raw.matchAll(IMPORT_SOURCE)) {
    const spec = match[1] ?? "";
    if (!FRAMEWORK_IMPORT.test(spec)) return true;
  }
  return /\b(?:await\s+import|require)\s*\(\s*["'](?:\.\.?\/|@?[a-z])/i.test(raw);
}

export function scanVitestConfigs(repo: DiscoveredRepo): Finding[] {
  const findings: Finding[] = [];
  for (const file of repo.files) {
    const base = path.posix.basename(file.rel);
    if (!VITEST_CONFIG_FILE.test(base)) continue;
    const isVitest =
      base.toLowerCase().startsWith("vitest.") ||
      /["']vitest\/config["']/.test(file.content) ||
      /\btest\s*:\s*\{/.test(file.content);
    if (!isVitest) continue;

    if (!PINS_UTC.test(file.content)) {
      findings.push({
        id: `TD:utc:${file.rel}`,
        rule: "vitest-missing-utc-tz",
        category: "test-smell",
        rung: "R0",
        severity: "warn",
        file: file.rel,
        line: 1,
        message: `${file.rel} does not pin test.env.TZ to "UTC".`,
        fix: 'Set test: { env: { TZ: "UTC" } } so date/time tests are identical across developer laptops and CI.',
      });
    }

    const missingRestore = MOCK_RESTORATION_CHECKS.filter((c) => !c.regex.test(file.content)).map((c) => c.key);
    if (missingRestore.length > 0) {
      findings.push({
        id: `TD:restore:${file.rel}`,
        rule: "vitest-missing-mock-restoration",
        category: "test-smell",
        rung: "R0",
        severity: "warn",
        file: file.rel,
        line: 1,
        message: `${file.rel} omits ${missingRestore.join(", ")}: true, risking mock/env leakage between tests.`,
        fix: "Enable restoreMocks: true, unstubGlobals: true, and unstubEnvs: true in Vitest config.",
      });
    }
  }
  return findings;
}
