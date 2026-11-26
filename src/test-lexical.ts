import path from "node:path";
import type { DiscoveredRepo, ScannedFile } from "./discover.ts";
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
const CSHARP_PARENT_NS_TEST =
  /^\s*namespace\s+[A-Za-z_][A-Za-z0-9_.]*\.(?:Unit|Integration|Functional|Component)?(?:Tests?|Specs?)\b/m;
const CSHARP_FRAMEWORK_TYPE =
  /^(?:Assert|Fact|Theory|Task|DateTime|DateTimeOffset|TimeSpan|Random|Thread|Environment|JsonSerializer|File|Path|Guid|Console|Math|String|Enumerable|List|Dictionary|HashSet|Array|Object|Exception|InvalidOperationException|ArgumentException|StringComparison|CancellationToken|HttpStatusCode|Stopwatch|Mock|Substitute)$/;

const VITEST_CONFIG_FILE = /^(?:vitest|vite)\.config\.[cm]?[jt]s$/i;
const PINS_UTC = /\benv\s*:\s*\{[^}]*\bTZ\s*:\s*["']UTC["']/;
const MOCK_RESTORATION_CHECKS = [
  { key: "restoreMocks", regex: /\brestoreMocks\s*:\s*true\b/ },
  { key: "unstubGlobals", regex: /\bunstubGlobals\s*:\s*true\b/ },
  { key: "unstubEnvs", regex: /\bunstubEnvs\s*:\s*true\b/ },
] as const;

function maskLexical(text: string, stripComments: boolean, language?: string): string {
  const isPython = language === "python";
  const out = [...text];
  let quote = "";
  let tripleQuote = "";
  let tripleLen = 0;
  let verbatimCSharp = false;
  let rustRawHashes = -1;
  let escaped = false;
  for (let i = 0; i < text.length; i++) {
    const ch = text[i] ?? "";
    const next = text[i + 1] ?? "";
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
        if (next === '"') {
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
      if (stripComments && isPython && ch === "#") {
        while (i < text.length && text[i] !== "\n") {
          out[i] = " ";
          i += 1;
        }
        continue;
      }
      if (stripComments && !isPython && ch === "/" && next === "/") {
        while (i < text.length && text[i] !== "\n") {
          out[i] = " ";
          i += 1;
        }
        continue;
      }
      if (stripComments && !isPython && ch === "/" && next === "*") {
        out[i] = " ";
        out[i + 1] = " ";
        i += 2;
        while (i < text.length) {
          if (text[i] === "*" && text[i + 1] === "/") {
            out[i] = " ";
            out[i + 1] = " ";
            i += 1;
            break;
          }
          if (text[i] !== "\n" && text[i] !== "\r") out[i] = " ";
          i += 1;
        }
        continue;
      }
      if (ch === "@" && next === '"') {
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
      if ((ch === '"' || ch === "'") && next === ch && text[i + 2] === ch) {
        let count = 3;
        while (text[i + count] === ch) count += 1;
        for (let k = 0; k < count; k++) out[i + k] = " ";
        i += count - 1;
        tripleQuote = ch;
        tripleLen = count;
        continue;
      }
      if (ch === '"' || ch === "'" || ch === "`") {
        if (language === "rust" && ch === "'" && (next === "_" || /[A-Za-z]/.test(next)) && (text[i + 2] ?? "") !== "'") {
          continue;
        }
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

export function maskStrings(text: string): string {
  return maskLexical(text, false);
}

export function maskCode(text: string, language?: string): string {
  return maskLexical(text, true, language);
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
      const masked = maskCode(raw, "csharp");
      for (const match of masked.matchAll(/\bnew\s+([A-Z][A-Za-z0-9_]*)\s*[<(]/g)) {
        const typeName = match[1] ?? "";
        if (!CSHARP_FRAMEWORK_TYPE.test(typeName)) return true;
      }
      for (const match of masked.matchAll(/\b([A-Z][A-Za-z0-9_]*)\.[A-Z][A-Za-z0-9_]*\s*[<(]/g)) {
        const typeName = match[1] ?? "";
        if (!CSHARP_FRAMEWORK_TYPE.test(typeName)) return true;
      }
      for (const match of masked.matchAll(/\bclass\s+[A-Za-z0-9_]+\s*:\s*([A-Z][A-Za-z0-9_]*)/g)) {
        const baseName = match[1] ?? "";
        if (!CSHARP_FRAMEWORK_TYPE.test(baseName)) return true;
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
  if (language === "go") {
    const goImports = [...raw.matchAll(/"([a-zA-Z0-9._/-]+)"/g)].map((m) => m[1] ?? "");
    if (goImports.some((imp) => imp.includes(".") && !/^(?:github\.com\/stretchr\/testify|pgregory\.net\/rapid)/.test(imp))) {
      return true;
    }
    const pkgMatch = /^\s*package\s+([a-zA-Z0-9_]+)/m.exec(raw);
    if (pkgMatch?.[1] && !pkgMatch[1].endsWith("_test")) {
      const masked = maskCode(raw, "go");
      for (const m of masked.matchAll(/\b([A-Za-z][A-Za-z0-9_]*)\s*\(/g)) {
        const fn = m[1] ?? "";
        if (!/^(?:Test[A-Z]|Benchmark[A-Z]|Fuzz[A-Z]|Example|if|for|switch|func|make|len|cap|append|new|delete|panic|recover|fmt|t|b|assert|require|rapid|errors|strings|bytes|time|context|json|os|filepath|http|httptest|testing)$/.test(fn)) {
          return true;
        }
      }
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

const CLOUD_SDK_IMPORT = /\bfrom\s*["'](?:firebase-admin|@google-cloud\/|@aws-sdk\/)|require\s*\(\s*["'](?:firebase-admin|@google-cloud\/)/;
const EMULATOR_GUARD = /\b(?:FIRESTORE_EMULATOR_HOST|FIREBASE_AUTH_EMULATOR_HOST|PUBSUB_EMULATOR_HOST|STORAGE_EMULATOR_HOST|initializeTestEnvironment|vi\.mock|jest\.mock)\b/;
const DAO_MOCK_PATH = /\b(?:vi|jest)\.mock\s*\(\s*["'][^"']*(?:\/dao\/|\/daos\/|\/repositories\/|\/repo\/)[^"']*["']/g;
const REPO_MUTATION_CALL =
  /\b(?:writeFileSync|writeFile|rmSync|unlinkSync|appendFileSync)\s*\(\s*(?:path\.(?:join|resolve)\s*\(\s*process\.cwd\(\)|["'](?:\.\.?\/)?(?:src|apps|packages|tools|\.github)\/)|\bexec(?:File)?Sync\s*\(\s*["']git["']\s*,\s*\[[^\]]*(?:commit|reset|checkout|clean|add)/g;

const HARDCODED_TEST_PORT =
  /(?:127\.0\.0\.1|localhost):(?:300\d|400\d|500\d|800\d|808\d|900\d)\b|\.\s*listen\s*\(\s*(?:300\d|400\d|500\d|800\d|808\d|900\d)\b/g;
const SKIP_IN_AFTER_HOOK = /\b(?:afterEach|afterAll)\s*\([\s\S]{0,220}?\b(?:test|it)\.skip\s*\(/g;
const LONG_UNREFD_TIMER = /\bsetTimeout\s*\([^,\n]+,\s*(?:[5-9]\d{3}|\d{5,})\s*\)/g;
const PY_GLOBAL_TEST_MUTATION = /\b(?:sys\.modules\s*\[[^\]]+\]\s*=|sys\.path\.(?:append|insert)\s*\()/g;

export function scanTestHarnessGuards(
  file: ScannedFile,
  raw: string,
  code: string,
  repoHasEmulator: boolean,
): Finding[] {
  const findings: Finding[] = [];

  for (const m of code.matchAll(HARDCODED_TEST_PORT)) {
    const idx = m.index ?? 0;
    const lineText = raw.split(/\r?\n/)[lineOf(raw, idx) - 1] ?? "";
    if (/^\s*(?:\/\/|#|\*)/.test(lineText) || /\b(?:mock|stub|baseUrl|example\.com|FIRESTORE_EMULATOR_HOST)\b/i.test(lineText)) {
      continue;
    }
    if (/\b(?:listen|bind|TcpListener|HTTPServer|createServer)\b/i.test(lineText)) {
      const line = lineOf(raw, idx);
      findings.push({
        id: `TH:static-loopback-port:${file.rel}:${line}`,
        rule: "test-hardcoded-loopback-port",
        category: "test-smell",
        rung: "R3",
        severity: "warn",
        file: file.rel,
        line,
        message: "Test binds a hardcoded loopback port, causing EADDRINUSE flakes under parallel test execution.",
        fix: "Bind port 0 (ephemeral OS-assigned port) and read the assigned address from the listener.",
      });
    }
  }

  if (file.language === "python") {
    if (!/\b(?:monkeypatch|patch\.dict)\b/.test(raw)) {
      for (const m of code.matchAll(PY_GLOBAL_TEST_MUTATION)) {
        const line = lineOf(raw, m.index ?? 0);
        findings.push({
          id: `TH:py-global-state:${file.rel}:${line}`,
          rule: "py-test-global-state-pollution",
          category: "test-smell",
          rung: "R2",
          severity: "warn",
          file: file.rel,
          line,
          message: `Test mutates global Python runtime state (${m[0].trim()}) without monkeypatch or mock.patch.dict cleanup.`,
          fix: "Use pytest monkeypatch.setitem/syspath_prepend or unittest.mock.patch.dict so state resets after the test.",
        });
      }
    }
    return findings;
  }

  if (file.language === "rust") {
    for (const m of code.matchAll(/\bassert_eq!\s*\([^;\n]*\.to_bits\s*\(\s*\)/g)) {
      const line = lineOf(raw, m.index ?? 0);
      findings.push({
        id: `TH:rs-float-bits:${file.rel}:${line}`,
        rule: "no-cross-platform-float-bit-golden",
        category: "test-smell",
        rung: "R2",
        severity: "warn",
        file: file.rel,
        line,
        message: "Bit-exact float assertion (.to_bits()) flakes across OS/CPU libm implementations (1-ULP transcendental drift).",
        fix: "Assert within an explicit ULP, epsilon, or dB tolerance instead of bit-exact float equality.",
      });
    }
    return findings;
  }
  if (file.language !== "typescript" && file.language !== "javascript") return findings;

  for (const m of code.matchAll(SKIP_IN_AFTER_HOOK)) {
    const line = lineOf(raw, m.index ?? 0);
    findings.push({
      id: `TH:skip-after:${file.rel}:${line}`,
      rule: "no-skip-in-after-hook",
      category: "cheat",
      rung: "R0",
      severity: "error",
      file: file.rel,
      line,
      message: "Calling test.skip() inside afterEach/afterAll aborts cleanup hooks and masks teardown failures.",
      fix: "Guard conditional skips at the top of the test or in beforeEach, never inside teardown hooks.",
    });
  }

  if (!/\.unref\s*\(\s*\)|\bclearTimeout\s*\(/.test(code)) {
    for (const m of code.matchAll(LONG_UNREFD_TIMER)) {
      const line = lineOf(raw, m.index ?? 0);
      findings.push({
        id: `TH:long-timer:${file.rel}:${line}`,
        rule: "no-unrefd-long-test-timer",
        category: "test-smell",
        rung: "R2",
        severity: "warn",
        file: file.rel,
        line,
        message: "Long setTimeout (>= 5s) in test without .unref() or clearTimeout keeps the event loop alive and stalls worker exit.",
        fix: "Call timer.unref(), clearTimeout in finally, or use fake timers / AbortSignal.timeout.",
      });
    }
  }

  if (CLOUD_SDK_IMPORT.test(raw) && !EMULATOR_GUARD.test(raw)) {
    const idx = raw.search(CLOUD_SDK_IMPORT);
    const line = lineOf(raw, Math.max(0, idx));
    findings.push({
      id: `TH:emulator-guard:${file.rel}:${line}`,
      rule: "test-require-emulator-guard",
      category: "test-smell",
      rung: "R4",
      severity: "error",
      file: file.rel,
      line,
      message: "Test imports a cloud/Firebase SDK without an emulator-host guard or test-environment bootstrap (risks hitting live cloud).",
      fix: "Require *_EMULATOR_HOST / initializeTestEnvironment before initializing cloud SDKs in tests.",
    });
  }

  if (repoHasEmulator) {
    for (const m of code.matchAll(/\b(?:vi|jest)\.mock\s*\(/g)) {
      const idx = m.index ?? 0;
      const slice = raw.slice(idx, idx + 120);
      if (!DAO_MOCK_PATH.test(slice)) continue;
      DAO_MOCK_PATH.lastIndex = 0;
      const line = lineOf(raw, idx);
      findings.push({
        id: `TH:dao-mock:${file.rel}:${line}`,
        rule: "no-dao-mock-with-fake-db",
        category: "test-smell",
        rung: "R3",
        severity: "warn",
        file: file.rel,
        line,
        message: "Test mocks a DAO/repository module in a repo that already provides an emulator or in-memory fake DB.",
        fix: "Exercise the real DAO against the in-memory fake DB or emulator so persistence/merge contracts stay verified.",
      });
    }
  }

  if (!/\b(?:mkdtemp|tmpdir|os\.tmpdir)\b/.test(raw)) {
    for (const m of raw.matchAll(REPO_MUTATION_CALL)) {
      const line = lineOf(raw, m.index ?? 0);
      findings.push({
        id: `TH:repo-mutate:${file.rel}:${line}`,
        rule: "test-repo-mutation-risk",
        category: "test-smell",
        rung: "R2",
        severity: "warn",
        file: file.rel,
        line,
        message: "Test writes files or mutates git inside the enclosing repo root without mkdtemp/tmpdir isolation.",
        fix: "Create an isolated directory with fs.mkdtempSync(path.join(os.tmpdir(), ...)) and clean it up in afterEach.",
      });
    }
  }

  if (/\bvi\.mock\s*\(/.test(code) && !/\bvi\.hoisted\s*\(/.test(code)) {
    const topDecls = new Set<string>();
    const mockIdx = code.search(/\bvi\.mock\s*\(/);
    const beforeMock = code.slice(0, Math.max(0, mockIdx));
    for (const d of beforeMock.matchAll(/^\s*(?:const|let)\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*=/gm)) {
      if (d[1]) topDecls.add(d[1]);
    }
    if (topDecls.size > 0) {
      const factoryMatch = /\bvi\.mock\s*\([^,\n]+,\s*(?:async\s*)?\(\s*[^)]*\)\s*=>\s*\{?([\s\S]{0,400})/.exec(
        code.slice(mockIdx),
      );
      const factoryBody = factoryMatch?.[1] ?? "";
      const referencedIds = new Set(factoryBody.match(/[A-Za-z_$][A-Za-z0-9_$]*/g) ?? []);
      for (const name of topDecls) {
        if (referencedIds.has(name)) {
          const line = lineOf(raw, mockIdx);
          findings.push({
            id: `TH:vi-hoist:${file.rel}:${line}`,
            rule: "vitest-mock-hoist-hazard",
            category: "test-smell",
            rung: "R0",
            severity: "error",
            file: file.rel,
            line,
            message: `vi.mock() factory references unhoisted local binding '${name}' (hoisting causes runtime ReferenceError or broken cleanup).`,
            fix: `Declare '${name}' inside vi.hoisted(() => ...) so it is initialized before vi.mock executes.`,
          });
          break;
        }
      }
    }
  }

  return findings;
}
