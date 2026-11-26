import { spawnSync, type SpawnSyncReturns } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { parse as parseToml } from "smol-toml";

const SAFE_ENV_EXACT = new Set([
  "PATH", "PATHEXT", "SYSTEMROOT", "COMSPEC", "WINDIR", "OS",
  "LANG", "TZ", "TERM", "NO_COLOR", "COLORTERM",
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
    if (SAFE_ENV_EXACT.has(k) || k.startsWith("LC_")) clean[k] = v;
  }
  clean.NO_COLOR = "1";
  return clean;
}

export function runGitClean(
  repoRoot: string,
  args: readonly string[],
  options: { maxBuffer?: number; timeout?: number } = {},
): SpawnSyncReturns<string> {
  const env: NodeJS.ProcessEnv = {};
  for (const [k, v] of Object.entries(process.env)) {
    if (v === undefined || k.startsWith("GIT_")) continue;
    env[k] = v;
  }
  return spawnSync("git", ["-C", repoRoot, "-c", "core.attributesFile=/dev/null", ...args], {
    encoding: "utf8",
    env,
    maxBuffer: options.maxBuffer ?? 16 * 1024 * 1024,
    timeout: options.timeout,
  });
}

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

function flattenTomlObj(obj: unknown, prefix: string[] = []): Array<{ path: string[]; key: string; value: unknown }> {
  const out: Array<{ path: string[]; key: string; value: unknown }> = [];
  if (Array.isArray(obj)) {
    for (const item of obj) {
      if (isRecord(item)) out.push(...flattenTomlObj(item, prefix));
    }
    return out;
  }
  if (!isRecord(obj)) return out;
  for (const [k, v] of Object.entries(obj)) {
    const next = [...prefix, k];
    const key = next.join(".").toLowerCase();
    out.push({ path: next, key, value: v });
    if (isRecord(v) || (Array.isArray(v) && v.some((x) => isRecord(x)))) {
      out.push(...flattenTomlObj(v, next));
    }
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

const BANNED_CARGO_KEYS = new Set([
  "runner", "rustc", "rustc-wrapper", "rustc-workspace-wrapper", "linker", "rustflags", "rustdocflags",
]);
const BANNED_CARGO_ENV = /^(?:RUSTC|RUSTC_WRAPPER|RUSTC_WORKSPACE_WRAPPER|RUSTFLAGS|CARGO_BUILD_|CARGO_TARGET_.*_RUNNER|LD_PRELOAD|DYLD_INSERT_LIBRARIES|VSTACK_)/i;

function auditCargoConfigContent(rel: string, raw: string): string | null {
  let doc: Record<string, unknown>;
  try {
    doc = parseToml(raw);
  } catch (err: unknown) {
    return `${rel} is invalid TOML (${err instanceof Error ? err.message : "parse error"}) — failing closed.`;
  }
  for (const entry of flattenTomlObj(doc)) {
    const first = (entry.path[0] ?? "").toLowerCase();
    const last = (entry.path[entry.path.length - 1] ?? "").toLowerCase();
    if (BANNED_CARGO_KEYS.has(last)) {
      return `${rel} declares '${entry.key}', which can hijack cargo test/build execution.`;
    }
    if (first === "env" && entry.path.length >= 2 && BANNED_CARGO_ENV.test(entry.path[1] ?? "")) {
      return `${rel} [env] sets disallowed variable '${entry.path[1]}'.`;
    }
  }
  return null;
}

const BAD_PYTEST_ADDOPTS = /(?:^|[\s"'[,])(?:-k\b|-m\b|--collect-only\b|--co\b|-o\b|--override-ini\b|--ignore(?:=|\s|$)|--ignore-glob(?:=|\s|$)|--deselect(?:=|\s|$)|-p\s+\S|--noconftest\b)/i;

function parseIniSections(raw: string): Array<{ section: string; key: string; value: string }> {
  const out: Array<{ section: string; key: string; value: string }> = [];
  let section = "";
  let cur: { section: string; key: string; value: string } | null = null;
  for (const line of raw.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#") || trimmed.startsWith(";")) continue;
    if (trimmed.startsWith("[") && trimmed.endsWith("]")) {
      section = trimmed.slice(1, -1).trim().toLowerCase();
      cur = null;
      continue;
    }
    if (/^\s+/.test(line) && cur) {
      cur.value = `${cur.value} ${trimmed}`;
      continue;
    }
    const m = /^([A-Za-z0-9_.-]+)\s*[:=]\s*(.*)$/.exec(trimmed);
    if (m?.[1]) {
      cur = { section, key: m[1].toLowerCase(), value: (m[2] ?? "").trim() };
      out.push(cur);
    }
  }
  return out;
}

function checkPytestOptions(rel: string, opts: Record<string, unknown>): string | null {
  for (const [k, v] of Object.entries(opts)) {
    const low = k.toLowerCase();
    const text = Array.isArray(v) ? v.map(String).join(" ") : typeof v === "string" ? v : "";
    if (low === "addopts" && BAD_PYTEST_ADDOPTS.test(text)) {
      return `${rel} pytest addopts narrows or alters test collection ('${text.slice(0, 60)}').`;
    }
    if (low === "python_files" && text && !/test/i.test(text)) {
      return `${rel} pytest python_files ('${text.slice(0, 50)}') excludes standard test_*.py files.`;
    }
    if (low === "norecursedirs" && /\btests?\b/i.test(text)) {
      return `${rel} pytest norecursedirs excludes test directories.`;
    }
  }
  return null;
}

function auditPytestFile(rel: string, raw: string): string | null {
  if (rel.endsWith(".toml")) {
    let doc: Record<string, unknown>;
    try {
      doc = parseToml(raw);
    } catch (err: unknown) {
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
      try {
        const err = auditBunfigContent(fs.readFileSync(bunfig, "utf8"));
        if (err) return err;
      } catch {
        return "unreadable bunfig.toml.";
      }
    }
    for (const rel of [".cargo/config.toml", ".cargo/config"]) {
      const cargoCfg = path.join(dir, rel);
      if (!fs.existsSync(cargoCfg)) continue;
      try {
        const err = auditCargoConfigContent(rel, fs.readFileSync(cargoCfg, "utf8"));
        if (err) return err;
      } catch {
        return `unreadable ${rel}.`;
      }
    }
    for (const rel of ["pyproject.toml", "pytest.toml", "pytest.ini", "setup.cfg", "tox.ini"]) {
      const p = path.join(dir, rel);
      if (!fs.existsSync(p)) continue;
      try {
        const err = auditPytestFile(rel, fs.readFileSync(p, "utf8"));
        if (err) return err;
      } catch {
        return `unreadable ${rel}.`;
      }
    }
  }
  return null;
}
