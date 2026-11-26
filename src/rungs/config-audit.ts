import { spawnSync, type SpawnSyncReturns } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { parse as parseToml } from "smol-toml";

const SAFE_ENV_EXACT = new Set([
  "PATH", "PATHEXT", "SYSTEMROOT", "COMSPEC", "WINDIR", "OS",
  "LANG", "LC_ALL", "LC_CTYPE", "LC_COLLATE", "LC_MESSAGES", "LC_NUMERIC", "LC_TIME", "LC_MONETARY",
  "TZ", "TERM", "NO_COLOR", "COLORTERM", "USER", "LOGNAME", "USERNAME", "SHELL",
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
  for (const [k, v] of Object.entries(baseEnv)) if (v !== undefined && SAFE_ENV_EXACT.has(k)) clean[k] = v;
  clean.NO_COLOR = "1";
  return clean;
}

const CLEAN_GIT_FLAGS = ["-c", "core.attributesFile=/dev/null", "-c", "diff.noprefix=false", "-c", "diff.mnemonicPrefix=false", "-c", "core.quotepath=false"];

function cleanGitEnv(): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = {};
  for (const [k, v] of Object.entries(process.env)) if (v !== undefined && !k.startsWith("GIT_")) env[k] = v;
  return env;
}

export function runGitClean(repoRoot: string, args: readonly string[], options: { maxBuffer?: number; timeout?: number } = {}): SpawnSyncReturns<string> {
  return spawnSync("git", ["-C", repoRoot, ...CLEAN_GIT_FLAGS, ...args], {
    encoding: "utf8", env: cleanGitEnv(), maxBuffer: options.maxBuffer ?? 16 * 1024 * 1024, timeout: options.timeout,
  });
}

export function runGitCleanBuffer(repoRoot: string, args: readonly string[], options: { maxBuffer?: number; timeout?: number } = {}): SpawnSyncReturns<Buffer> {
  return spawnSync("git", ["-C", repoRoot, ...CLEAN_GIT_FLAGS, ...args], {
    env: cleanGitEnv(), maxBuffer: options.maxBuffer ?? 32 * 1024 * 1024, timeout: options.timeout,
  });
}

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

function flattenTomlObj(obj: unknown, prefix: string[] = []): Array<{ path: string[]; key: string; value: unknown }> {
  const out: Array<{ path: string[]; key: string; value: unknown }> = [];
  if (Array.isArray(obj)) { for (const item of obj) if (isRecord(item)) out.push(...flattenTomlObj(item, prefix)); return out; }
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
  try { doc = parseToml(raw); } catch (err: unknown) {
    return `bunfig.toml is invalid TOML (${err instanceof Error ? err.message : "parse error"}) — failing closed.`;
  }
  for (const [topKey, topVal] of Object.entries(doc)) {
    const low = topKey.toLowerCase();
    if (low === "preload" || low === "loader" || low === "define" || low === "jsx") return `bunfig.toml declares '${topKey}', which can intercept or alter test execution.`;
    if (low === "run" && isRecord(topVal)) {
      for (const rk of Object.keys(topVal)) if (rk.toLowerCase() === "preload") return "bunfig.toml declares [run].preload, which can intercept test runners.";
    }
    if (low === "test" && isRecord(topVal)) {
      for (const [tk, tv] of Object.entries(topVal)) {
        const tlow = tk.toLowerCase();
        if (!SAFE_BUNFIG_TEST_KEYS.has(tlow)) return `bunfig.toml declares disallowed [test].${tk} (positive test-config key allowlist).`;
        if (tlow === "reruneach" && typeof tv === "number" && tv < 1) return "bunfig.toml [test].rerunEach must be >= 1.";
      }
    }
  }
  for (const entry of flattenTomlObj(doc)) {
    if ((entry.path[entry.path.length - 1] ?? "").toLowerCase() === "preload") return `bunfig.toml declares '${entry.key}', which can intercept test runners.`;
  }
  return null;
}

const SAFE_CARGO_TABLES = new Set(["net", "http", "term", "registries", "registry", "build", "future-incompat-report"]);
const SAFE_CARGO_BUILD_KEYS = new Set(["jobs", "incremental", "target-dir", "pipelining"]);
const CRITICAL_CARGO_LINTS = new Set(["all", "warnings", "correctness", "suspicious", "complexity", "perf", "unsafe_code", "unwrap_used", "expect_used", "panic", "dead_code"]);

function auditCargoConfigContent(rel: string, raw: string): string | null {
  let doc: Record<string, unknown>;
  try { doc = parseToml(raw); } catch (err: unknown) {
    return `${rel} is invalid TOML (${err instanceof Error ? err.message : "parse error"}) — failing closed.`;
  }
  for (const [topKey, topVal] of Object.entries(doc)) {
    const low = topKey.toLowerCase();
    if (!SAFE_CARGO_TABLES.has(low)) return `${rel} declares disallowed section [${topKey}] (positive cargo config allowlist).`;
    if (low === "build" && isRecord(topVal)) {
      for (const bk of Object.keys(topVal)) if (!SAFE_CARGO_BUILD_KEYS.has(bk.toLowerCase())) return `${rel} declares disallowed [build].${bk}.`;
    }
  }
  return null;
}

function checkCargoLintsTable(rel: string, lints: Record<string, unknown>, prefix: string[]): string | null {
  for (const entry of flattenTomlObj(lints, prefix)) {
    const leaf = (entry.path[entry.path.length - 1] ?? "").toLowerCase();
    const parent = (entry.path[entry.path.length - 2] ?? "").toLowerCase();
    if (entry.value === "allow" && CRITICAL_CARGO_LINTS.has(leaf)) return `${rel} weakens critical compiler/clippy lint '${entry.key} = "allow"'.`;
    if (leaf === "level" && entry.value === "allow" && CRITICAL_CARGO_LINTS.has(parent)) return `${rel} weakens critical compiler/clippy lint '${entry.key} = "allow"'.`;
  }
  return null;
}

function auditCargoManifest(rel: string, raw: string): { error: string | null; memberGlobs: string[] } {
  let doc: Record<string, unknown>;
  try { doc = parseToml(raw); } catch { return { error: null, memberGlobs: [] }; }
  const pkg = isRecord(doc.package) ? doc.package : undefined;
  if (pkg && (pkg.autotests === false || pkg.autobins === false)) return { error: `${rel} disables test/bin discovery (autotests=false).`, memberGlobs: [] };
  for (const section of ["lib", "bin", "test"]) {
    const val = doc[section];
    for (const item of Array.isArray(val) ? val : isRecord(val) ? [val] : []) {
      if (isRecord(item) && item.test === false) return { error: `${rel} sets test = false in [${section}].`, memberGlobs: [] };
    }
  }
  if (isRecord(doc.lints)) {
    const err = checkCargoLintsTable(rel, doc.lints, ["lints"]);
    if (err) return { error: err, memberGlobs: [] };
  }
  const memberGlobs: string[] = [];
  if (isRecord(doc.workspace)) {
    if (Array.isArray(doc.workspace["default-members"]) && doc.workspace["default-members"].length > 0) {
      return { error: `${rel} narrows workspace tests via [workspace].default-members.`, memberGlobs };
    }
    if (Array.isArray(doc.workspace.exclude) && doc.workspace.exclude.length > 0) {
      return { error: `${rel} excludes workspace crates via [workspace].exclude.`, memberGlobs };
    }
    if (isRecord(doc.workspace.lints)) {
      const err = checkCargoLintsTable(rel, doc.workspace.lints, ["workspace", "lints"]);
      if (err) return { error: err, memberGlobs };
    }
    if (Array.isArray(doc.workspace.members)) {
      for (const m of doc.workspace.members) if (typeof m === "string") memberGlobs.push(m);
    }
  }
  return { error: null, memberGlobs };
}

function auditNextestConfig(rel: string, raw: string): string | null {
  let doc: Record<string, unknown>;
  try { doc = parseToml(raw); } catch (err: unknown) {
    return `${rel} is invalid TOML (${err instanceof Error ? err.message : "parse error"}) — failing closed.`;
  }
  for (const entry of flattenTomlObj(doc)) {
    const last = (entry.path[entry.path.length - 1] ?? "").toLowerCase();
    if (last === "default-filter" || last === "filter-override" || last === "status-level") return `${rel} declares '${entry.key}', which can filter or silence nextest runs.`;
  }
  return null;
}

function tokenizeSimpleArgs(text: string): string[] {
  const out: string[] = []; let cur = ""; let q = "";
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

const SAFE_PYTEST_BOOL = new Set(["-q", "-v", "-vv", "-x", "-ra", "-s", "--strict-markers", "--strict-config", "--color=yes", "--color=no", "--color=auto"]);
const SAFE_PYTEST_VALUE = new Set(["--junitxml", "--cov", "--cov-report", "--cov-fail-under", "--tb", "--timeout", "--maxfail", "-n", "--color"]);

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
  let section = ""; let cur: { section: string; key: string; value: string } | null = null;
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

function checkPytestOptions(rel: string, opts: Record<string, unknown>, dir: string): string | null {
  for (const [k, v] of Object.entries(opts)) {
    const low = k.toLowerCase();
    const list = Array.isArray(v) ? v.map(String) : typeof v === "string" ? v.split(/[\s,]+/).filter(Boolean) : [];
    const text = Array.isArray(v) ? v.map(String).join(" ") : typeof v === "string" ? v : "";
    if (low === "addopts" && text.trim()) { const err = auditPytestAddopts(rel, text); if (err) return err; }
    if (low === "python_files" && list.length > 0 && !list.some((p) => /^(?:test_\*\.py|\*_test\.py)$/.test(p))) return `${rel} pytest python_files narrows standard test_*.py discovery.`;
    if (low === "python_classes" && list.length > 0 && !list.some((p) => /^Test\*?$/.test(p))) return `${rel} pytest python_classes narrows test class discovery.`;
    if (low === "python_functions" && list.length > 0 && !list.some((p) => /^test_\*?$/.test(p))) return `${rel} pytest python_functions narrows test function discovery.`;
    if (low === "norecursedirs" && list.some((p) => p === "*" || p === "**" || /^(?:t\*|te\*|tes\*|test\*)|\btests?\b/i.test(p))) return `${rel} pytest norecursedirs excludes test directories.`;
    if (low === "testpaths" && list.length > 0) {
      const hasRealTests = fs.existsSync(path.join(dir, "tests")) || fs.existsSync(path.join(dir, "test"));
      if (list.some((p) => /\.py$/i.test(p) || p.includes("/")) || (hasRealTests && !list.some((p) => /^tests?$/i.test(p)))) {
        return `${rel} pytest testpaths ('${text.slice(0, 50)}') narrows test collection.`;
      }
    }
  }
  return null;
}

function auditPytestFile(rel: string, raw: string, dir: string): string | null {
  if (rel.endsWith(".toml")) {
    let doc: Record<string, unknown>;
    try { doc = parseToml(raw); } catch (err: unknown) {
      return `${rel} is invalid TOML (${err instanceof Error ? err.message : "parse error"}) — failing closed.`;
    }
    const tool = isRecord(doc.tool) ? doc.tool : undefined;
    const pytestNode = isRecord(tool?.pytest) ? tool.pytest : isRecord(doc.pytest) ? doc.pytest : undefined;
    if (pytestNode) {
      const errTop = checkPytestOptions(rel, pytestNode, dir);
      if (errTop) return errTop;
      if (isRecord(pytestNode.ini_options)) {
        const errIni = checkPytestOptions(rel, pytestNode.ini_options, dir);
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
  for (const rec of bySection.values()) { const err = checkPytestOptions(rel, rec, dir); if (err) return err; }
  return null;
}

const JS_TEST_CONFIG_FILES = [
  "vitest.config.ts", "vitest.config.mts", "vitest.config.js", "vitest.config.mjs", "vitest.config.cjs",
  "vite.config.ts", "vite.config.mts", "vite.config.js", "vite.config.mjs", "vite.config.cjs",
  "jest.config.ts", "jest.config.js", "jest.config.mjs", "jest.config.cjs", "jest.config.json",
];

export const VERIFICATION_TOOLS = new Set([
  "vitest", "jest", "mocha", "ava", "oxlint", "oxfmt", "eslint", "prettier", "biome",
  "typescript", "tsc", "tsgo", "veristack", "vstack", "playwright", "cypress", "knip", "stryker",
]);

function auditJsTestConfig(rel: string, raw: string): string | null {
  if (/\bpassWithNoTests["']?\s*[:=]\s*true\b/i.test(raw)) return `${rel} sets passWithNoTests: true.`;
  if (/\b(?:setupFiles|setupFilesAfterEnv|globalSetup)["']?\s*[:=]\s*[["'`]/i.test(raw)) return `${rel} declares setupFiles/globalSetup hook that can alter test runtime.`;
  if (/\b(?:testNamePattern|testMatch|testRegex|roots|rootDir|dir)["']?\s*[:=]\s*[["'`/]/i.test(raw)) return `${rel} overrides test discovery/matching via testNamePattern/testMatch/roots/dir.`;
  const ignoreMatch = /\btestPathIgnorePatterns["']?\s*[:=]\s*\[([^\]]*)\]/i.exec(raw);
  if (ignoreMatch?.[1]) {
    const items = [...ignoreMatch[1].matchAll(/["']([^"']+)["']/g)].map((m) => m[1] ?? "");
    if (items.some((it) => !/^\/?node_modules\/?$/.test(it.trim()))) return `${rel} ignores non-node_modules paths in testPathIgnorePatterns.`;
  }
  if (/\binclude["']?\s*[:=]\s*\[[^\]]*\.(?:test|spec)\.[cm]?[jt]sx?/i.test(raw)) return `${rel} narrows test include to explicit test filename(s).`;
  if (/\bexclude["']?\s*[:=]\s*\[[^\]]*["'](?:\*\*\/\*|\*\*\/tests?\/\*\*|tests?\/\*\*)["']/i.test(raw)) return `${rel} excludes test directories from execution.`;
  return null;
}

const LOCAL_SPEC_RE = /^(?:file:|link:|portal:|workspace:|\.\.?\/|\/|git\+|https?:)|\.tgz$/i;

function auditPackageToolShadowing(dir: string, rel: string, raw: string, absRoot: string): string | null {
  try {
    const pkg = JSON.parse(raw) as Record<string, unknown>;
    for (const bagKey of ["dependencies", "devDependencies", "optionalDependencies", "peerDependencies", "overrides", "resolutions"]) {
      const bag = pkg[bagKey];
      if (!isRecord(bag)) continue;
      for (const [k, v] of Object.entries(bag)) {
        const val = typeof v === "string" ? v.trim() : "";
        if (!val) continue;
        if (VERIFICATION_TOOLS.has(k.toLowerCase()) && LOCAL_SPEC_RE.test(val)) {
          return `${rel} (${bagKey}) overrides verification tool '${k}' with non-registry spec '${val}'.`;
        }
        if (LOCAL_SPEC_RE.test(val)) {
          const cleanLocal = val.replace(/^(?:file:|link:|portal:)/i, "");
          if (/\.tgz$/i.test(cleanLocal)) {
            if (VERIFICATION_TOOLS.has(k.toLowerCase()) || /(?:typescript|tsc|vitest|jest|oxlint|eslint|vstack|veristack)/i.test(cleanLocal)) {
              return `${rel} (${bagKey}) installs local verification-tool tarball '${val}'.`;
            }
          } else {
            const subPkg = path.resolve(dir, cleanLocal, "package.json");
            if (fs.existsSync(subPkg) && fs.statSync(subPkg).isFile()) {
              try {
                const subDoc = JSON.parse(fs.readFileSync(subPkg, "utf8")) as { bin?: string | Record<string, string> };
                if (isRecord(subDoc.bin)) {
                  for (const binName of Object.keys(subDoc.bin)) {
                    if (VERIFICATION_TOOLS.has(binName.toLowerCase())) return `${rel} (${bagKey}) local package '${k}' shadows verification binary '${binName}'.`;
                  }
                }
              } catch { void 0; }
            }
          }
        }
      }
    }
    if (isRecord(pkg.bin)) {
      const pkgName = typeof pkg.name === "string" ? pkg.name.toLowerCase() : "";
      for (const binName of Object.keys(pkg.bin)) {
        const low = binName.toLowerCase();
        if (pkgName === "veristack" && (low === "veristack" || low === "vstack")) continue;
        if (VERIFICATION_TOOLS.has(low)) return `${rel} declares bin '${binName}' shadowing a verification tool.`;
      }
    }
    if (isRecord(pkg.jest)) {
      const err = auditJsTestConfig(`${rel}#jest`, JSON.stringify(pkg.jest));
      if (err) return err;
    }
    const nmBin = path.join(dir, "node_modules", ".bin");
    if (fs.existsSync(nmBin) && fs.statSync(nmBin).isDirectory()) {
      const realRoot = (() => { try { return fs.realpathSync(absRoot); } catch { return absRoot; } })();
      const realNm = (() => { try { return fs.realpathSync(path.join(dir, "node_modules")); } catch { return path.join(dir, "node_modules"); } })();
      for (const tool of VERIFICATION_TOOLS) {
        const binEntry = path.join(nmBin, tool);
        if (!fs.existsSync(binEntry)) continue;
        try {
          const resolved = fs.realpathSync(binEntry);
          const insideRepo = resolved === realRoot || resolved.startsWith(`${realRoot}${path.sep}`);
          const insideNm = resolved === realNm || resolved.startsWith(`${realNm}${path.sep}`);
          if (insideRepo && !insideNm) return `node_modules/.bin/${tool} resolves outside node_modules (${path.relative(realRoot, resolved)}).`;
        } catch { continue; }
      }
    }
  } catch { return null; }
  return null;
}

const PY_SHADOW_FILES = ["sitecustomize.py", "usercustomize.py", "pytest.py", "unittest.py", "mypy.py", "ruff.py", "mutmut.py", "vulture.py"];
const PY_SHADOW_DIRS = ["pytest", "unittest", "mypy", "ruff", "mutmut", "vulture"];
const CONFTEST_TAMPER = /\b(?:pytest_collection_modifyitems|pytest_ignore_collect|pytest_runtest_makereport|pytest_configure|pytest_sessionfinish|session\.exitstatus\s*=|items\.clear\s*\(|items\s*\[\s*:\s*\]\s*=)/m;

function auditPythonShadowing(dir: string): string | null {
  for (const checkDir of [dir, path.join(dir, "src")]) {
    if (!fs.existsSync(checkDir) || !fs.statSync(checkDir).isDirectory()) continue;
    for (const f of PY_SHADOW_FILES) {
      if (fs.existsSync(path.join(checkDir, f))) return `Python runtime/tool shadowing file '${f}' is forbidden.`;
    }
    for (const d of PY_SHADOW_DIRS) {
      if (fs.existsSync(path.join(checkDir, d, "__init__.py"))) return `Python package '${d}/' shadows verification tool '${d}'.`;
    }
    for (const entry of fs.readdirSync(checkDir)) {
      if (entry.endsWith(".pth")) return `Python .pth hook '${entry}' can inject startup code.`;
    }
  }
  return null;
}

const WALK_SKIP = new Set([".git", "node_modules", "target", ".venv", "venv", "dist", "examples", "obj", "bin", "__pycache__"]);

function discoverRepoConfigDirs(absRoot: string): string[] {
  const dirs = new Set<string>([absRoot]);
  const walk = (cur: string, depth: number): void => {
    if (depth > 3) return;
    let entries: fs.Dirent[];
    try { entries = fs.readdirSync(cur, { withFileTypes: true }); } catch { return; }
    for (const e of entries) {
      if (e.isSymbolicLink()) continue;
      if (e.isDirectory()) {
        if (WALK_SKIP.has(e.name)) continue;
        walk(path.join(cur, e.name), depth + 1);
      } else if (e.name === "conftest.py" || e.name === ".pytest.toml" || e.name === "pytest.ini" || e.name === "Cargo.toml" || e.name === "bunfig.toml") {
        dirs.add(cur);
      }
    }
  };
  walk(absRoot, 0);
  return [...dirs];
}

export function auditRunnerConfigs(repoRoot: string, extraDirs: readonly string[] = []): string | null {
  const absRoot = path.resolve(repoRoot);
  const dirSet = new Set<string>(discoverRepoConfigDirs(absRoot));
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
    const pyErr = auditPythonShadowing(dir);
    if (pyErr) return pyErr;
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
      try { const res = auditCargoManifest("Cargo.toml", fs.readFileSync(cargoToml, "utf8")); if (res.error) return res.error; } catch { return "unreadable Cargo.toml."; }
    }
    const nextest = path.join(dir, ".config", "nextest.toml");
    if (fs.existsSync(nextest)) {
      try { const err = auditNextestConfig(".config/nextest.toml", fs.readFileSync(nextest, "utf8")); if (err) return err; } catch { return "unreadable .config/nextest.toml."; }
    }
    for (const rel of ["pyproject.toml", "pytest.toml", ".pytest.toml", "pytest.ini", "setup.cfg", "tox.ini"]) {
      const p = path.join(dir, rel);
      if (fs.existsSync(p)) {
        try { const err = auditPytestFile(rel, fs.readFileSync(p, "utf8"), dir); if (err) return err; } catch { return `unreadable ${rel}.`; }
      }
    }
    const conftest = path.join(dir, "conftest.py");
    if (fs.existsSync(conftest)) {
      try {
        if (CONFTEST_TAMPER.test(fs.readFileSync(conftest, "utf8"))) return `${path.relative(absRoot, conftest)} alters pytest collection/reporting or overrides exitstatus.`;
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
      try { const err = auditPackageToolShadowing(dir, "package.json", fs.readFileSync(pkgPath, "utf8"), absRoot); if (err) return err; } catch { void 0; }
    }
  }
  return null;
}
