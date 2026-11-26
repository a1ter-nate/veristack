import { spawnSync, type SpawnSyncReturns } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { parse as parseToml } from "smol-toml";

const SAFE_ENV_EXACT = new Set([
  "PATH", "PATHEXT", "SYSTEMROOT", "COMSPEC", "WINDIR", "OS",
  "LANG", "LC_ALL", "LC_CTYPE", "LC_COLLATE", "LC_MESSAGES", "LC_NUMERIC", "LC_TIME", "LC_MONETARY",
  "TZ", "TERM", "NO_COLOR", "COLORTERM",
  "USER", "LOGNAME", "USERNAME", "SHELL",
  "HOME", "USERPROFILE", "TMPDIR", "TMP", "TEMP",
  "CI", "GITHUB_ACTIONS", "GITHUB_RUN_ID", "GITHUB_SHA", "GITHUB_REF",
  "GITHUB_BASE_REF", "GITHUB_HEAD_REF", "GITHUB_REPOSITORY",
  "BUN_INSTALL", "DOTNET_ROOT", "DOTNET_CLI_HOME", "DOTNET_NOLOGO",
  "GOPATH", "GOROOT", "GOMODCACHE", "GOCACHE",
  "RUSTUP_HOME", "VIRTUAL_ENV", "NUGET_PACKAGES",
  "APPDATA", "LOCALAPPDATA", "PROGRAMFILES", "XDG_CACHE_HOME", "XDG_RUNTIME_DIR",
]);

export function scrubChildEnv(baseEnv: NodeJS.ProcessEnv = process.env): NodeJS.ProcessEnv {
  const clean: NodeJS.ProcessEnv = {};
  for (const [k, v] of Object.entries(baseEnv)) {
    if (v === undefined) continue;
    if (SAFE_ENV_EXACT.has(k)) clean[k] = v;
  }
  clean.NO_COLOR = "1";
  return clean;
}

const CLEAN_GIT_FLAGS = [
  "-c", "core.attributesFile=/dev/null",
  "-c", "diff.noprefix=false",
  "-c", "diff.mnemonicPrefix=false",
  "-c", "core.quotepath=false",
];

function cleanGitEnv(): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = {};
  for (const [k, v] of Object.entries(process.env)) {
    if (v === undefined || k.startsWith("GIT_")) continue;
    env[k] = v;
  }
  return env;
}

export function runGitClean(
  repoRoot: string,
  args: readonly string[],
  options: { maxBuffer?: number; timeout?: number } = {},
): SpawnSyncReturns<string> {
  return spawnSync("git", ["-C", repoRoot, ...CLEAN_GIT_FLAGS, ...args], {
    encoding: "utf8",
    env: cleanGitEnv(),
    maxBuffer: options.maxBuffer ?? 16 * 1024 * 1024,
    timeout: options.timeout,
  });
}

export function runGitCleanBuffer(
  repoRoot: string,
  args: readonly string[],
  options: { maxBuffer?: number; timeout?: number } = {},
): SpawnSyncReturns<Buffer> {
  return spawnSync("git", ["-C", repoRoot, ...CLEAN_GIT_FLAGS, ...args], {
    env: cleanGitEnv(),
    maxBuffer: options.maxBuffer ?? 32 * 1024 * 1024,
    timeout: options.timeout,
  });
}

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

function flattenTomlObj(obj: unknown, prefix: string[] = []): Array<{ path: string[]; key: string; value: unknown }> {
  const out: Array<{ path: string[]; key: string; value: unknown }> = [];
  if (Array.isArray(obj)) {
    for (const item of obj) if (isRecord(item)) out.push(...flattenTomlObj(item, prefix));
    return out;
  }
  if (!isRecord(obj)) return out;
  for (const [k, v] of Object.entries(obj)) {
    const next = [...prefix, k];
    out.push({ path: next, key: next.join(".").toLowerCase(), value: v });
    if (isRecord(v) || (Array.isArray(v) && v.some((x) => isRecord(x)))) out.push(...flattenTomlObj(v, next));
  }
  return out;
}

const SAFE_BUNFIG_TEST_KEYS = new Set([
  "coverage", "coveragethreshold", "coverageskiptestfiles", "coveragereporter",
  "coveragedir", "coveragepathignorepatterns", "timeout", "smol", "bail",
  "retry", "reruneach", "concurrent", "randomize", "seed",
]);

export function auditBunfigContent(raw: string): string | null {
  let doc: Record<string, unknown>;
  try {
    doc = parseToml(raw);
  } catch (err: unknown) {
    return `bunfig.toml is invalid TOML (${err instanceof Error ? err.message : "parse error"}) — failing closed.`;
  }
  for (const [topKey, topVal] of Object.entries(doc)) {
    const low = topKey.toLowerCase();
    if (low === "preload" || low === "loader" || low === "define" || low === "jsx") {
      return `bunfig.toml declares '${topKey}', which can intercept or alter test execution.`;
    }
    if (low === "run" && isRecord(topVal)) {
      for (const rk of Object.keys(topVal)) {
        if (rk.toLowerCase() === "preload") return "bunfig.toml declares [run].preload, which can intercept test runners.";
      }
    }
    if (low === "test" && isRecord(topVal)) {
      for (const [tk, tv] of Object.entries(topVal)) {
        const tlow = tk.toLowerCase();
        if (!SAFE_BUNFIG_TEST_KEYS.has(tlow)) {
          return `bunfig.toml declares disallowed [test].${tk} (positive test-config key allowlist).`;
        }
        if (tlow === "reruneach" && typeof tv === "number" && tv < 1) {
          return "bunfig.toml [test].rerunEach must be >= 1.";
        }
      }
    }
  }
  for (const entry of flattenTomlObj(doc)) {
    const last = (entry.path[entry.path.length - 1] ?? "").toLowerCase();
    if (last === "preload") return `bunfig.toml declares '${entry.key}', which can intercept test runners.`;
  }
  return null;
}

const SAFE_CARGO_TABLES = new Set(["net", "http", "term", "registries", "registry", "build", "future-incompat-report"]);
const SAFE_CARGO_BUILD_KEYS = new Set(["jobs", "incremental", "target-dir", "pipelining"]);

function auditCargoConfigContent(rel: string, raw: string): string | null {
  let doc: Record<string, unknown>;
  try {
    doc = parseToml(raw);
  } catch (err: unknown) {
    return `${rel} is invalid TOML (${err instanceof Error ? err.message : "parse error"}) — failing closed.`;
  }
  for (const [topKey, topVal] of Object.entries(doc)) {
    const low = topKey.toLowerCase();
    if (!SAFE_CARGO_TABLES.has(low)) {
      return `${rel} declares disallowed section [${topKey}] (positive cargo config allowlist; blocks [env]/[alias]/[target]/[patch]/[source]).`;
    }
    if (low === "build" && isRecord(topVal)) {
      for (const bk of Object.keys(topVal)) {
        if (!SAFE_CARGO_BUILD_KEYS.has(bk.toLowerCase())) {
          return `${rel} declares disallowed [build].${bk} (can hijack rustc/rustflags/linker).`;
        }
      }
    }
  }
  return null;
}

function auditCargoManifest(rel: string, raw: string): string | null {
  let doc: Record<string, unknown>;
  try {
    doc = parseToml(raw);
  } catch {
    return null;
  }
  const pkg = isRecord(doc.package) ? doc.package : undefined;
  if (pkg && (pkg.autotests === false || pkg.autobins === false)) {
    return `${rel} disables test/bin discovery (autotests=false).`;
  }
  for (const section of ["lib", "bin", "test"]) {
    const val = doc[section];
    const items = Array.isArray(val) ? val : isRecord(val) ? [val] : [];
    for (const item of items) {
      if (isRecord(item) && item.test === false) return `${rel} sets test = false in [${section}].`;
    }
  }
  const lints = isRecord(doc.lints) ? doc.lints : undefined;
  if (lints) {
    const criticalLints = new Set(["all", "warnings", "correctness", "suspicious", "complexity", "perf", "unsafe_code", "unwrap_used", "expect_used", "panic", "dead_code"]);
    for (const entry of flattenTomlObj(lints, ["lints"])) {
      const lintName = (entry.path[entry.path.length - 1] ?? "").toLowerCase();
      if (entry.value === "allow" && criticalLints.has(lintName)) return `${rel} weakens critical compiler/clippy lint '${entry.key} = "allow"'.`;
    }
  }
  return null;
}

function auditNextestConfig(rel: string, raw: string): string | null {
  let doc: Record<string, unknown>;
  try {
    doc = parseToml(raw);
  } catch (err: unknown) {
    return `${rel} is invalid TOML (${err instanceof Error ? err.message : "parse error"}) — failing closed.`;
  }
  for (const entry of flattenTomlObj(doc)) {
    const last = (entry.path[entry.path.length - 1] ?? "").toLowerCase();
    if (last === "default-filter" || last === "filter-override" || last === "status-level") {
      return `${rel} declares '${entry.key}', which can filter or silence nextest runs.`;
    }
  }
  return null;
}

function tokenizeSimpleArgs(text: string): string[] {
  const out: string[] = [];
  let cur = ""; let q = "";
  for (let i = 0; i < text.length; i++) {
    const ch = text[i] ?? "";
    if (q) { if (ch === q) q = ""; else cur += ch; continue; }
    if (ch === '"' || ch === "'") { q = ch; continue; }
    if (/\s/.test(ch)) { if (cur) { out.push(cur); cur = ""; } continue; }
    cur += ch;
  }
  if (cur) out.push(cur);
  return out;
}

const SAFE_PYTEST_BOOL = new Set(["-q", "-v", "-vv", "-x", "-ra", "-s", "--strict-markers", "--strict-config", "--color=yes", "--color=no", "--color=auto", "--benchmark-only", "--benchmark-enable"]);
const SAFE_PYTEST_VALUE = new Set(["--junitxml", "--cov", "--cov-report", "--cov-fail-under", "--tb", "--timeout", "--maxfail", "--benchmark-min-rounds", "-n", "--color"]);

function auditPytestAddopts(rel: string, text: string): string | null {
  const tokens = tokenizeSimpleArgs(text);
  for (let i = 0; i < tokens.length; i++) {
    const tok = tokens[i] ?? "";
    if (!tok) continue;
    if (!tok.startsWith("-")) return `${rel} pytest addopts injects positional selector '${tok}'.`;
    const eq = tok.indexOf("=");
    const flag = eq > 0 ? tok.slice(0, eq) : tok;
    if (SAFE_PYTEST_BOOL.has(tok) || (eq < 0 && SAFE_PYTEST_BOOL.has(flag))) continue;
    if (SAFE_PYTEST_VALUE.has(flag)) { if (eq < 0) i += 1; continue; }
    return `${rel} pytest addopts uses disallowed flag '${tok}' (positive pytest addopts allowlist).`;
  }
  return null;
}

function parseIniSections(raw: string): Array<{ section: string; key: string; value: string }> {
  const out: Array<{ section: string; key: string; value: string }> = [];
  let section = "";
  let cur: { section: string; key: string; value: string } | null = null;
  for (const line of raw.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#") || trimmed.startsWith(";")) continue;
    if (trimmed.startsWith("[") && trimmed.endsWith("]")) { section = trimmed.slice(1, -1).trim().toLowerCase(); cur = null; continue; }
    if (/^\s+/.test(line) && cur) { cur.value = `${cur.value} ${trimmed}`; continue; }
    const m = /^([A-Za-z0-9_.-]+)\s*[:=]\s*(.*)$/.exec(trimmed);
    if (m?.[1]) { cur = { section, key: m[1].toLowerCase(), value: (m[2] ?? "").trim() }; out.push(cur); }
  }
  return out;
}

function checkPytestOptions(rel: string, opts: Record<string, unknown>): string | null {
  for (const [k, v] of Object.entries(opts)) {
    const low = k.toLowerCase();
    const list = Array.isArray(v) ? v.map(String) : typeof v === "string" ? v.split(/[\s,]+/).filter(Boolean) : [];
    const text = Array.isArray(v) ? v.map(String).join(" ") : typeof v === "string" ? v : "";
    if (low === "addopts" && text.trim()) {
      const err = auditPytestAddopts(rel, text);
      if (err) return err;
    }
    if (low === "python_files" && list.length > 0 && !list.some((p) => /^(?:test_\*\.py|\*_test\.py)$/.test(p))) {
      return `${rel} pytest python_files ('${text.slice(0, 50)}') narrows standard test_*.py discovery.`;
    }
    if (low === "python_classes" && list.length > 0 && !list.some((p) => /^Test\*?$/.test(p))) {
      return `${rel} pytest python_classes ('${text.slice(0, 50)}') narrows test class discovery.`;
    }
    if (low === "python_functions" && list.length > 0 && !list.some((p) => /^test_\*?$/.test(p))) {
      return `${rel} pytest python_functions ('${text.slice(0, 50)}') narrows test function discovery.`;
    }
    if (low === "norecursedirs" && list.some((p) => p === "*" || p === "**" || /^t\*$|\btests?\b/i.test(p))) {
      return `${rel} pytest norecursedirs ('${text.slice(0, 50)}') excludes test directories.`;
    }
    if (low === "testpaths" && list.some((p) => /\.py$/i.test(p) || p.includes("/"))) {
      return `${rel} pytest testpaths ('${text.slice(0, 50)}') narrows collection to a specific file or subpath.`;
    }
  }
  return null;
}

function auditPytestFile(rel: string, raw: string): string | null {
  if (rel.endsWith(".toml")) {
    let doc: Record<string, unknown>;
    try { doc = parseToml(raw); } catch (err: unknown) {
      return `${rel} is invalid TOML (${err instanceof Error ? err.message : "parse error"}) — failing closed.`;
    }
    const tool = isRecord(doc.tool) ? doc.tool : undefined;
    const pytestNode = isRecord(tool?.pytest) ? tool.pytest : isRecord(doc.pytest) ? doc.pytest : undefined;
    if (pytestNode) {
      const errTop = checkPytestOptions(rel, pytestNode);
      if (errTop) return errTop;
      if (isRecord(pytestNode.ini_options)) {
        const errIni = checkPytestOptions(rel, pytestNode.ini_options);
        if (errIni) return errIni;
      }
    }
    return null;
  }
  const bySection = new Map<string, Record<string, string>>();
  for (const item of parseIniSections(raw)) {
    if (!/(?:^|:)pytest$/.test(item.section) && item.section !== "tool:pytest") continue;
    const rec = bySection.get(item.section) ?? {};
    rec[item.key] = item.value;
    bySection.set(item.section, rec);
  }
  for (const rec of bySection.values()) {
    const err = checkPytestOptions(rel, rec);
    if (err) return err;
  }
  return null;
}

const JS_TEST_CONFIG_FILES = [
  "vitest.config.ts", "vitest.config.mts", "vitest.config.js", "vitest.config.mjs", "vitest.config.cjs",
  "jest.config.ts", "jest.config.js", "jest.config.mjs", "jest.config.cjs", "jest.config.json",
];
const SHADOWED_TOOLS = new Set(["vitest", "jest", "mocha", "ava", "oxlint", "eslint", "typescript", "veristack", "playwright", "cypress"]);

function auditJsTestConfig(rel: string, raw: string): string | null {
  if (/\bpassWithNoTests\s*:\s*true\b/i.test(raw)) return `${rel} sets passWithNoTests: true.`;
  if (/\b(?:testNamePattern|testPathIgnorePatterns)\s*[:=]\s*[["'`]/.test(raw) && !/node_modules/.test(raw.slice(raw.search(/\b(?:testNamePattern|testPathIgnorePatterns)\b/), raw.search(/\b(?:testNamePattern|testPathIgnorePatterns)\b/) + 80))) {
    return `${rel} narrows test execution via testNamePattern/testPathIgnorePatterns.`;
  }
  if (/\binclude\s*:\s*\[\s*["'][^"']*\.(?:test|spec)\.[cm]?[jt]sx?["']\s*\]/.test(raw)) {
    return `${rel} narrows include to a single test file.`;
  }
  if (/\bexclude\s*:\s*\[[^\]]*["'](?:\*\*\/\*|\*\*\/tests?\/\*\*|tests?\/\*\*)["']/.test(raw)) {
    return `${rel} excludes test directories from execution.`;
  }
  return null;
}

function auditPackageToolShadowing(rel: string, raw: string): string | null {
  try {
    const pkg = JSON.parse(raw) as { dependencies?: Record<string, string>; devDependencies?: Record<string, string> };
    for (const bag of [pkg.dependencies, pkg.devDependencies]) {
      if (!bag || typeof bag !== "object") continue;
      for (const [k, v] of Object.entries(bag)) {
        if (SHADOWED_TOOLS.has(k.toLowerCase()) && typeof v === "string" && /^(?:file:|link:)/i.test(v.trim())) {
          return `${rel} overrides verification tool '${k}' with local '${v}'.`;
        }
      }
    }
  } catch { return null; }
  return null;
}

export function auditRunnerConfigs(repoRoot: string, extraDirs: readonly string[] = []): string | null {
  const dirSet = new Set<string>([path.resolve(repoRoot)]);
  const absRoot = path.resolve(repoRoot);
  for (const d of extraDirs) {
    let cur = path.resolve(d);
    while (cur === absRoot || cur.startsWith(`${absRoot}${path.sep}`)) {
      dirSet.add(cur);
      const parent = path.dirname(cur);
      if (parent === cur) break;
      cur = parent;
    }
  }
  for (const dir of dirSet) {
    const bunfig = path.join(dir, "bunfig.toml");
    if (fs.existsSync(bunfig)) {
      try { const err = auditBunfigContent(fs.readFileSync(bunfig, "utf8")); if (err) return err; } catch { return "unreadable bunfig.toml."; }
    }
    for (const rel of [".cargo/config.toml", ".cargo/config"]) {
      const cargoCfg = path.join(dir, rel);
      if (fs.existsSync(cargoCfg)) {
        try { const err = auditCargoConfigContent(rel, fs.readFileSync(cargoCfg, "utf8")); if (err) return err; } catch { return `unreadable ${rel}.`; }
      }
    }
    const cargoToml = path.join(dir, "Cargo.toml");
    if (fs.existsSync(cargoToml)) {
      try { const err = auditCargoManifest("Cargo.toml", fs.readFileSync(cargoToml, "utf8")); if (err) return err; } catch { return "unreadable Cargo.toml."; }
    }
    const nextest = path.join(dir, ".config", "nextest.toml");
    if (fs.existsSync(nextest)) {
      try { const err = auditNextestConfig(".config/nextest.toml", fs.readFileSync(nextest, "utf8")); if (err) return err; } catch { return "unreadable .config/nextest.toml."; }
    }
    for (const rel of ["pyproject.toml", "pytest.toml", "pytest.ini", "setup.cfg", "tox.ini"]) {
      const p = path.join(dir, rel);
      if (fs.existsSync(p)) {
        try { const err = auditPytestFile(rel, fs.readFileSync(p, "utf8")); if (err) return err; } catch { return `unreadable ${rel}.`; }
      }
    }
    const conftest = path.join(dir, "conftest.py");
    if (fs.existsSync(conftest)) {
      try {
        const raw = fs.readFileSync(conftest, "utf8");
        if (/\b(?:pytest_collection_modifyitems|pytest_sessionfinish|session\.exitstatus\s*=|items\.clear\s*\()/m.test(raw)) {
          return "conftest.py alters pytest collection or overrides session.exitstatus.";
        }
      } catch { return "unreadable conftest.py."; }
    }
    for (const rel of JS_TEST_CONFIG_FILES) {
      const p = path.join(dir, rel);
      if (fs.existsSync(p)) {
        try { const err = auditJsTestConfig(rel, fs.readFileSync(p, "utf8")); if (err) return err; } catch { return `unreadable ${rel}.`; }
      }
    }
    const pkgPath = path.join(dir, "package.json");
    if (fs.existsSync(pkgPath)) {
      try { const err = auditPackageToolShadowing("package.json", fs.readFileSync(pkgPath, "utf8")); if (err) return err; } catch { void 0; }
    }
  }
  return null;
}
