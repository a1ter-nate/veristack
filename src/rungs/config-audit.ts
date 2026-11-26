import fs from "node:fs";
import path from "node:path";

const HIJACK_ENV_EXACT = new Set([
  "VSTACK_RECEIPT_KEY", "VSTACK_ALLOW_MANIFEST_CHANGE", "VSTACK_HOOK_DISABLED",
  "GITHUB_TOKEN", "GH_TOKEN", "NPM_TOKEN", "NODE_AUTH_TOKEN", "ACTIONS_RUNTIME_TOKEN",
  "FORCE_COLOR", "CLICOLOR_FORCE", "NODE_OPTIONS", "PYTEST_ADDOPTS", "GOFLAGS",
  "RUSTFLAGS", "CARGO_BUILD_RUSTC_WRAPPER", "RUSTC_WRAPPER", "DOTNET_STARTUP_HOOKS",
  "BUN_OPTIONS", "PYTHONSTARTUP", "PYTHONPATH", "RUBYOPT", "PERL5OPT",
]);

export function scrubChildEnv(baseEnv: NodeJS.ProcessEnv = process.env): NodeJS.ProcessEnv {
  const clean: NodeJS.ProcessEnv = {};
  for (const [k, v] of Object.entries(baseEnv)) {
    if (v === undefined) continue;
    if (HIJACK_ENV_EXACT.has(k) || k.startsWith("VSTACK_") || k.startsWith("ACTIONS_ID_TOKEN_")) continue;
    if (/^CARGO_TARGET_.*_RUNNER$/i.test(k)) continue;
    clean[k] = v;
  }
  clean.NO_COLOR = "1";
  return clean;
}

function unescapeTomlKey(raw: string): string {
  const t = raw.trim();
  if ((t.startsWith('"') && t.endsWith('"')) || (t.startsWith("'") && t.endsWith("'"))) {
    const inner = t.slice(1, -1);
    return t.startsWith('"')
      ? inner.replace(/\\u([0-9a-fA-F]{4})/g, (_, h: string) => String.fromCharCode(parseInt(h, 16))).replace(/\\"/g, '"')
      : inner;
  }
  return t;
}

function splitRespectingQuotes(input: string, sep: string): string[] {
  const out: string[] = [];
  let cur = "";
  let quote = "";
  let depth = 0;
  for (let i = 0; i < input.length; i++) {
    const ch = input[i] ?? "";
    if (quote) {
      cur += ch;
      if (ch === "\\" && quote === '"' && i + 1 < input.length) { cur += input[i + 1] ?? ""; i += 1; continue; }
      if (ch === quote) quote = "";
      continue;
    }
    if (ch === '"' || ch === "'") { quote = ch; cur += ch; continue; }
    if (ch === "{" || ch === "[") { depth += 1; cur += ch; continue; }
    if ((ch === "}" || ch === "]") && depth > 0) { depth -= 1; cur += ch; continue; }
    if (ch === sep && depth === 0) { out.push(cur.trim()); cur = ""; continue; }
    cur += ch;
  }
  if (cur.trim()) out.push(cur.trim());
  return out;
}

function stripTomlComment(line: string): string {
  let quote = "";
  for (let i = 0; i < line.length; i++) {
    const ch = line[i] ?? "";
    if (quote) {
      if (ch === "\\" && quote === '"' && i + 1 < line.length) { i += 1; continue; }
      if (ch === quote) quote = "";
      continue;
    }
    if (ch === '"' || ch === "'") { quote = ch; continue; }
    if (ch === "#") return line.slice(0, i);
  }
  return line;
}

function collectTomlFlatEntries(raw: string): Array<{ key: string; value: string }> {
  const entries: Array<{ key: string; value: string }> = [];
  let section: string[] = [];
  const addPair = (prefix: string[], rawKey: string, rawVal: string): void => {
    const segs = splitRespectingQuotes(rawKey, ".").map(unescapeTomlKey).filter(Boolean);
    const full = [...prefix, ...segs];
    const val = rawVal.trim();
    if (val.startsWith("{") && val.endsWith("}")) {
      for (const item of splitRespectingQuotes(val.slice(1, -1), ",")) {
        const eq = item.indexOf("=");
        if (eq > 0) addPair(full, item.slice(0, eq), item.slice(eq + 1));
      }
      return;
    }
    entries.push({ key: full.join(".").toLowerCase(), value: val });
  };

  for (const rawLine of raw.split(/\r?\n/)) {
    const line = stripTomlComment(rawLine).trim();
    if (!line) continue;
    if (line.startsWith("[[") && line.endsWith("]]")) {
      section = splitRespectingQuotes(line.slice(2, -2), ".").map(unescapeTomlKey).filter(Boolean);
      continue;
    }
    if (line.startsWith("[") && line.endsWith("]")) {
      section = splitRespectingQuotes(line.slice(1, -1), ".").map(unescapeTomlKey).filter(Boolean);
      continue;
    }
    let eq = -1;
    let quote = "";
    for (let i = 0; i < line.length; i++) {
      const ch = line[i] ?? "";
      if (quote) {
        if (ch === "\\" && quote === '"') { i += 1; continue; }
        if (ch === quote) quote = "";
        continue;
      }
      if (ch === '"' || ch === "'") quote = ch;
      else if (ch === "=") { eq = i; break; }
    }
    if (eq > 0) addPair(section, line.slice(0, eq), line.slice(eq + 1));
  }
  return entries;
}

export function auditBunfigContent(raw: string): string | null {
  const entries = collectTomlFlatEntries(raw);
  for (const { key } of entries) {
    if (key === "preload" || key.endsWith(".preload")) {
      return "bunfig.toml declares 'preload', which can intercept test runners.";
    }
    if (key === "test.root") {
      return "bunfig.toml overrides [test].root, which can redirect test discovery.";
    }
  }
  return null;
}

export function auditRunnerConfigs(repoRoot: string, extraDirs: readonly string[] = []): string | null {
  const dirs = [repoRoot, ...extraDirs];
  for (const dir of dirs) {
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
        const entries = collectTomlFlatEntries(fs.readFileSync(cargoCfg, "utf8"));
        for (const { key } of entries) {
          if (key === "runner" || key.endsWith(".runner") || key === "build.rustc-wrapper" || key === "build.rustc-workspace-wrapper") {
            return `${rel} declares '${key}', which can hijack cargo test/build execution.`;
          }
        }
      } catch {
        return `unreadable ${rel}.`;
      }
    }
    for (const rel of ["pyproject.toml", "pytest.ini", "setup.cfg"]) {
      const p = path.join(dir, rel);
      if (!fs.existsSync(p)) continue;
      try {
        const raw = fs.readFileSync(p, "utf8");
        const entries = rel.endsWith(".toml") ? collectTomlFlatEntries(raw) : [];
        const addoptsVals: string[] = entries.filter((e) => e.key.endsWith("pytest.ini_options.addopts") || e.key === "addopts").map((e) => e.value);
        if (!rel.endsWith(".toml")) {
          for (const m of raw.matchAll(/^\s*addopts\s*=\s*(.+)$/gm)) if (m[1]) addoptsVals.push(m[1]);
        }
        for (const val of addoptsVals) {
          if (/(?:^|[\s"'[,])(?:-k|-m|--collect-only|--co|-o\s+python_files|--ignore=|-p\s+no:)/i.test(val)) {
            return `${rel} pytest addopts narrows or disables test collection ('${val.slice(0, 60)}').`;
          }
        }
      } catch {
        continue;
      }
    }
  }
  return null;
}
