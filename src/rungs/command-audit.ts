import { spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import type { RungId } from "../types.ts";
import { auditRunnerConfigs, scrubChildEnv } from "./config-audit.ts";

export { scrubChildEnv };

const SHELL_META_UNQUOTED = /[;|><$`(){}\n\r~]/;
const FORBIDDEN_VERBS = new Set([
  "echo", "printf", "true", "false", ":", "sleep", "exit", "exec", "eval", "alias",
  "source", ".", "diff", "kill", "trap", "env", "sh", "bash", "zsh", "cmd", "powershell",
]);

const VERISTACK_ROOT_REALPATH = (() => {
  let dir = path.dirname(fileURLToPath(import.meta.url));
  for (let i = 0; i < 5; i++) {
    if (fs.existsSync(path.join(dir, "bin", "vstack.mjs")) && fs.existsSync(path.join(dir, "package.json"))) {
      try { return fs.realpathSync(dir); } catch { return dir; }
    }
    const parent = path.dirname(dir); if (parent === dir) break; dir = parent;
  }
  return path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
})();

interface RunnerFlagSchema { boolFlags: ReadonlySet<string>; valueFlags: ReadonlySet<string>; doubleDashMode?: "clippy" | "cargo-test"; }

const s = (...items: string[]): ReadonlySet<string> => new Set(items);
const PATH_VALUE_FLAGS = s("-c", "--config", "--config-path", "--config-file", "-p", "--project", "--manifest-path", "--coverage", "--directory", "--cwd", "--ignore-path", "--outfile", "--outdir", "--outputFile", "--reporter-outfile", "--results-directory", "--junitxml", "-o", "--out", "--output", "--coverprofile", "--corpus", "--replay", "--baseline", "-s", "-t");
const REPORTER_VALUE_FLAGS = s("--reporter", "--reporters", "--test-reporter", "-f", "--format");
const BUILTIN_REPORTERS = s("default", "verbose", "dot", "json", "junit", "tap", "spec", "nyan", "min", "list", "line", "html", "github-actions", "trx", "console", "basic", "hanging-process", "blob", "stylish", "compact", "unix", "checkstyle", "sarif", "progress", "documentation", "lcov");

const RUNNER_SCHEMAS: Record<string, RunnerFlagSchema> = {
  oxlint: { boolFlags: s("--deny-warnings", "--quiet", "--fix-suggestions", "--type-aware"), valueFlags: s("-c", "--config", "-f", "--format", "-D") },
  oxfmt: { boolFlags: s("--check"), valueFlags: s("-c", "--config") },
  eslint: { boolFlags: s("--quiet", "--no-warn-ignored"), valueFlags: s("-c", "--config", "--max-warnings", "--ext", "-f", "--format") },
  prettier: { boolFlags: s("--check", "-c"), valueFlags: s("--config", "--ignore-path") },
  biome: { boolFlags: s("--error-on-warnings"), valueFlags: s("--config-path", "--reporter") },
  ruff: { boolFlags: s("check", "format", "--check", "--diff", "--no-fix", "--quiet"), valueFlags: s("--config", "--output-format") },
  "golangci-lint": { boolFlags: s("run", "--fast"), valueFlags: s("-c", "--config", "--timeout") },
  gofmt: { boolFlags: s("-l", "-d", "-s"), valueFlags: s() }, goimports: { boolFlags: s("-l", "-d"), valueFlags: s() },
  dprint: { boolFlags: s("check"), valueFlags: s("-c", "--config") }, stylua: { boolFlags: s("--check"), valueFlags: s("-f", "--config-path") },
  rubocop: { boolFlags: s("--fail-fast"), valueFlags: s("-c", "--config", "-f", "--format") }, ktlint: { boolFlags: s(), valueFlags: s("--reporter") },
  checkstyle: { boolFlags: s(), valueFlags: s("-c") }, vulture: { boolFlags: s(), valueFlags: s("--min-confidence") },
  tsc: { boolFlags: s("--noEmit", "--strict", "--pretty", "--incremental", "--composite", "-b", "--build", "--skipLibCheck"), valueFlags: s("-p", "--project") },
  tsgo: { boolFlags: s("--noEmit", "--strict", "--pretty", "-b", "--build", "--skipLibCheck"), valueFlags: s("-p", "--project") },
  mypy: { boolFlags: s("--strict", "--no-error-summary", "--show-error-codes"), valueFlags: s("--config-file", "--python-version") },
  pyright: { boolFlags: s("--warnings", "--stats"), valueFlags: s("-p", "--project", "--pythonversion") }, basedpyright: { boolFlags: s("--warnings", "--stats"), valueFlags: s("-p", "--project") },
  knip: { boolFlags: s("--no-progress", "--strict"), valueFlags: s("-c", "--config", "-W", "--workspace") }, "deslop-please": { boolFlags: s("--strict", "--json"), valueFlags: s("-c", "--config") },
  deadcode: { boolFlags: s("-test"), valueFlags: s() }, staticcheck: { boolFlags: s(), valueFlags: s("-checks", "-f") }, "import-linter": { boolFlags: s(), valueFlags: s("--config") },
  vitest: { boolFlags: s("run", "--run", "--coverage", "--bail"), valueFlags: s("--reporter", "--outputFile", "--testTimeout") },
  jest: { boolFlags: s("--ci", "--coverage", "--bail", "--runInBand", "--no-cache"), valueFlags: s("--reporters", "--testTimeout") },
  mocha: { boolFlags: s("--bail", "--recursive"), valueFlags: s("--reporter", "--timeout") }, ava: { boolFlags: s("--fail-fast", "--verbose"), valueFlags: s("--timeout") },
  pytest: { boolFlags: s("-q", "-v", "-vv", "-x", "-ra", "--strict-markers", "--benchmark-only", "--benchmark-enable"), valueFlags: s("--junitxml", "--cov", "--cov-report", "--cov-fail-under", "--tb", "--timeout", "--maxfail", "--benchmark-min-rounds", "-n") },
  phpunit: { boolFlags: s("--stop-on-failure"), valueFlags: s("--log-junit") }, rspec: { boolFlags: s("--fail-fast"), valueFlags: s("-f", "--format", "-o", "--out") },
  unittest: { boolFlags: s("discover", "-v", "-f"), valueFlags: s("-s", "-t") },
  "bun test": { boolFlags: s("--bail", "--coverage"), valueFlags: s("--timeout", "--reporter", "--reporter-outfile", "--concurrency", "--rerun-each") },
  "bun build": { boolFlags: s("--minify", "--sourcemap"), valueFlags: s("--outfile", "--outdir", "--target", "--external", "--format") },
  "node --test": { boolFlags: s("--experimental-test-coverage"), valueFlags: s("--test-reporter", "--test-reporter-destination", "--test-timeout") },
  "dotnet build": { boolFlags: s("--warnaserror", "--no-restore", "-warnaserror"), valueFlags: s("-c", "--configuration", "-v", "--verbosity") },
  "dotnet format": { boolFlags: s("--verify-no-changes", "--no-restore"), valueFlags: s("-v", "--verbosity") },
  "dotnet test": { boolFlags: s("--no-build", "--no-restore"), valueFlags: s("-c", "--configuration", "-v", "--verbosity", "--logger", "--results-directory", "--collect") },
  "dotnet stryker": { boolFlags: s(), valueFlags: s("-p", "--project", "-r", "--reporter", "-o", "--output") },
  "dotnet run": { boolFlags: s("--no-build"), valueFlags: s("-c", "--configuration", "--project") },
  "cargo fmt": { boolFlags: s("--check", "--all"), valueFlags: s("--manifest-path") },
  "cargo clippy": { boolFlags: s("--all-targets", "--all-features", "--workspace", "--locked", "--no-default-features"), valueFlags: s("--manifest-path", "-p", "--package", "--features"), doubleDashMode: "clippy" },
  "cargo check": { boolFlags: s("--all-targets", "--all-features", "--workspace", "--locked", "--no-default-features"), valueFlags: s("--manifest-path", "-p", "--package", "--features") },
  "cargo test": { boolFlags: s("--all-targets", "--all-features", "--workspace", "--locked", "--lib", "--bins", "--tests", "--no-default-features", "--release"), valueFlags: s("--manifest-path", "-p", "--package", "--features"), doubleDashMode: "cargo-test" },
  "cargo nextest": { boolFlags: s("run", "--all-features", "--workspace", "--locked", "--no-default-features", "--release"), valueFlags: s("--manifest-path", "-p", "--package", "--profile", "--features") },
  "cargo bench": { boolFlags: s("--all-features", "--workspace", "--locked", "--no-default-features"), valueFlags: s("--manifest-path", "-p", "--package", "--bench", "--features") },
  "cargo mutants": { boolFlags: s("--workspace", "--in-place"), valueFlags: s("--manifest-path", "-p", "--package", "-j", "--jobs", "--timeout") },
  "cargo deny": { boolFlags: s("check"), valueFlags: s("--manifest-path") }, "cargo machete": { boolFlags: s("--with-metadata"), valueFlags: s() }, "cargo udeps": { boolFlags: s("--all-targets"), valueFlags: s("--manifest-path") },
  "go vet": { boolFlags: s(), valueFlags: s("-tags", "-mod") }, "go build": { boolFlags: s("-race"), valueFlags: s("-o", "-tags", "-mod") },
  "go test": { boolFlags: s("-v", "-race", "-count=1", "-benchmem", "-cover", "-json"), valueFlags: s("-count", "-timeout", "-coverprofile", "-covermode", "-fuzz", "-fuzztime", "-bench", "-benchtime", "-tags", "-mod") },
  stryker: { boolFlags: s("run"), valueFlags: s("--reporters", "--concurrency", "--mutate") }, mutmut: { boolFlags: s("run", "results"), valueFlags: s("--paths-to-mutate", "--tests-dir") },
  gremlins: { boolFlags: s("unleash"), valueFlags: s("--threshold-efficacy", "--tags") }, bend: { boolFlags: s("--verdict", "--check-only"), valueFlags: s() },
  quint: { boolFlags: s("verify", "run", "typecheck"), valueFlags: s("--invariant", "--max-steps", "--max-samples") }, dafny: { boolFlags: s("verify"), valueFlags: s("--verification-time-limit") },
  kani: { boolFlags: s("--tests"), valueFlags: s("--manifest-path", "--harness") }, playwright: { boolFlags: s("test"), valueFlags: s("--project", "--reporter", "--workers", "--timeout") },
  cypress: { boolFlags: s("run"), valueFlags: s("--browser", "--spec", "--reporter") }, k6: { boolFlags: s("run"), valueFlags: s("--vus", "--duration", "--out", "--summary-export") },
  hyperfine: { boolFlags: s(), valueFlags: s("--warmup", "--runs", "--min-runs", "--export-json") },
  vstack: { boolFlags: s("--fail", "--strict", "--verify", "--json", "--md", "--check-github"), valueFlags: s("--test-cmd", "--targets", "--base", "--max-mutants", "--min-kill-rate", "--coverage", "--max-crap", "--max-time-exp", "--max-space-exp", "--corpus", "--replay", "--baseline") },
};

const ALLOWED_TOOL_PREFIXES: Record<RungId | "canary", readonly RegExp[]> = {
  R0: [/^(?:oxlint|oxfmt|eslint|prettier|biome|ruff|golangci-lint|gofmt|goimports|vstack|dprint|stylua|rubocop|ktlint|checkstyle)$/, /^(?:cargo\s+(?:fmt|clippy)|dotnet\s+(?:format|build)|node\s+bin\/vstack\.mjs|bun\s+src\/cli\.ts)$/],
  R1: [/^(?:tsc|tsgo|mypy|pyright|basedpyright|knip|deslop-please|vulture|deadcode|staticcheck|import-linter)$/, /^(?:cargo\s+(?:check|clippy|udeps|machete|deny)|dotnet\s+build|go\s+(?:vet|build)|bun\s+build|node\s+scripts\/check-max-lines\.mjs|bun\s+scripts\/check-max-lines\.mjs)$/],
  R2: [/^(?:vitest|jest|mocha|ava|pytest|phpunit|rspec|xunit|nunit|ctest|unittest)$/, /^(?:bun\s+test|node\s+--test|dotnet\s+test|cargo\s+(?:test|nextest)|go\s+test)$/],
  R3: [/^(?:vitest|jest|pytest|pact|pact-go|storybook|schemathesis)$/, /^(?:bun\s+test|node\s+--test|dotnet\s+test|cargo\s+(?:test|nextest)|go\s+test)$/],
  R4: [/^(?:vitest|jest|pytest|prisma|alembic|flyway|goose|golang-migrate|drizzle-kit)$/, /^(?:bun\s+test|node\s+--test|dotnet\s+test|cargo\s+(?:test|nextest)|go\s+test)$/],
  R5: [/^(?:stryker|mutmut|pitest|gremlins|go-mutesting|crosshair|bend|quint|dafny|kani|stateright|chromatic|percy|argos|bombadil|vstack|pytest)$/, /^(?:cargo\s+(?:mutants|test|nextest)|dotnet\s+(?:stryker|test)|go\s+test|node\s+bin\/vstack\.mjs|bun\s+src\/cli\.ts)$/],
  R6: [/^(?:k6|lighthouse|lhci|locust|mitata|tinybench|divan|nbomber|hyperfine|criterion|vstack|pytest)$/, /^(?:cargo\s+bench|go\s+test|dotnet\s+run|node\s+bin\/vstack\.mjs|bun\s+src\/cli\.ts|bun\s+scripts\/check-perf-budget\.mjs|node\s+scripts\/check-perf-budget\.mjs)$/],
  R7: [/^(?:playwright|cypress|maestro|detox|webdriverio|wdio|pytest)$/, /^(?:go\s+test|cargo\s+(?:test|nextest)|dotnet\s+test|bun\s+test)$/],
  R8: [/^(?:k6|playwright|curl|synthetic|canary|smoke-prod|healthcheck)$/],
  canary: [/^(?:vitest|jest|mocha|ava|pytest|phpunit|rspec|xunit|nunit|ctest|unittest)$/, /^(?:bun\s+test|node\s+--test|dotnet\s+test|cargo\s+(?:test|nextest)|go\s+test|(?:bun|node)\s+\S+\.(?:test|spec)\.[cm]?[jt]sx?)$/],
};

const ALLOWED_VSTACK_BY_RUNG: Record<RungId | "canary", ReadonlySet<string>> = {
  R0: s("no-comments", "state-machines", "perimeter", "doctor", "bench", "diff-cheats"),
  R1: s("state-machines", "diff-cheats", "no-comments"), R2: s("canary", "oracle-check"),
  R3: s("formal-sync", "laws", "oracle-check"), R4: s("formal-sync", "oracle-check"),
  R5: s("canary", "formal-sync", "laws", "crap", "oracle-check"), R6: s("big-o", "spc"),
  R7: s("oracle-check"), R8: s("spc"), canary: s("canary"),
};
const VSTACK_REQUIRES_FAIL = s("canary", "formal-sync", "laws", "bench", "no-comments", "state-machines", "perimeter", "crap", "diff-cheats", "big-o", "spc", "doctor");

function stripShellComment(line: string): string {
  let inSingle = false; let inDouble = false;
  for (let i = 0; i < line.length; i++) {
    const ch = line[i] ?? "";
    if (ch === "'" && !inDouble) inSingle = !inSingle;
    else if (ch === '"' && !inSingle && line[i - 1] !== "\\") inDouble = !inDouble;
    else if (ch === "#" && !inSingle && !inDouble && (i === 0 || /\s/.test(line[i - 1] ?? ""))) return line.slice(0, i);
  }
  return line;
}

function joinLineContinuations(script: string): string[] {
  const joined: string[] = []; let buf = "";
  for (const raw of script.split(/\r?\n/)) {
    const t = raw.replace(/\s+$/, "");
    if (t.endsWith("\\")) buf += `${t.slice(0, -1)} `; else { joined.push(buf + raw); buf = ""; }
  }
  if (buf) joined.push(buf); return joined;
}

function sanitizeShellLines(runScript: string): string[] {
  const active: string[] = [];
  if (!runScript) return active;
  let setPlusE = false; let pipefail = false; let heredocEnd: string | null = null;
  let inFunction = false; let braceDepth = 0; let ifDepth = 0; let loopDepth = 0; let caseDepth = 0;
  for (const raw of joinLineContinuations(runScript)) {
    const trimmedRaw = raw.trim();
    if (heredocEnd !== null) { if (trimmedRaw === heredocEnd) heredocEnd = null; continue; }
    const hdMatch = /<<-?\s*['"]?([A-Za-z0-9_]+)['"]?/.exec(raw);
    if (hdMatch?.[1]) { heredocEnd = hdMatch[1]; continue; }
    const trimmed = stripShellComment(raw).trim();
    if (!trimmed) continue;
    if (inFunction) { braceDepth += (trimmed.match(/\{/g) ?? []).length - (trimmed.match(/\}/g) ?? []).length; if (braceDepth <= 0) { inFunction = false; braceDepth = 0; } continue; }
    if (/^(?:function\s+[A-Za-z_]\w*|[A-Za-z_]\w*\s*\(\s*\))\s*\{?/.test(trimmed)) { inFunction = true; braceDepth = (trimmed.match(/\{/g) ?? []).length - (trimmed.match(/\}/g) ?? []).length; if (braceDepth <= 0 && trimmed.includes("}")) inFunction = false; continue; }
    if (/^if\s+/.test(trimmed)) { if (!/\bfi\b/.test(trimmed)) ifDepth += 1; continue; }
    if (/^fi(?:\s|;|$)/.test(trimmed)) { ifDepth = Math.max(0, ifDepth - 1); continue; }
    if (/^(?:for|while|until)\s+/.test(trimmed)) { if (!/\bdone\b/.test(trimmed)) loopDepth += 1; continue; }
    if (/^done(?:\s|;|$)/.test(trimmed)) { loopDepth = Math.max(0, loopDepth - 1); continue; }
    if (/^case\s+/.test(trimmed)) { if (!/\besac\b/.test(trimmed)) caseDepth += 1; continue; }
    if (/^esac(?:\s|;|$)/.test(trimmed)) { caseDepth = Math.max(0, caseDepth - 1); continue; }
    if (ifDepth > 0 || loopDepth > 0 || caseDepth > 0) continue;
    if (/^set\s+(?:\+e|\+o\s+errexit)\b/.test(trimmed)) { setPlusE = true; continue; }
    if (/^set\s+(?:-e|-o\s+errexit)\b/.test(trimmed)) { setPlusE = false; if (/pipefail/.test(trimmed)) pipefail = true; continue; }
    if (/^set\s+-o\s+pipefail\b/.test(trimmed)) { pipefail = true; continue; }
    if (/^(?:exit(?:\s+\d+)?|exec\b)/.test(trimmed)) break;
    if (setPlusE) continue;
    if (/^(?:elif\s+|else\b|then\b|alias\s+|\$\{\{|!(\s|$)|\[{1,2}\s+|test\s+|[A-Za-z0-9_*?|]+\))/.test(trimmed) || /^(?:echo|printf|true|sleep|:)(?:\s|;|$)/.test(trimmed) || /^false(?:\s|&&|\|\||;|$)/.test(trimmed) || /^\.\/vstack\b/.test(trimmed) || /\|\|/.test(trimmed) || /;\s*(?:true|echo|printf|:|exit)(?:\s|$)/.test(trimmed) || /(?:^|[^&>])&(?!&|>)/.test(trimmed) || /&&\s*(?:echo|printf|true|:)(?:\s|$)/.test(trimmed) || (!pipefail && /(?:^|[^|\\])\|(?!\|)/.test(trimmed)) || /\s(?:--help|-h|--version|-V|--list-tests)(?:\s|$)/.test(trimmed)) continue;
    active.push(trimmed);
  }
  return active;
}

export function sanitizeShellBlock(runScript: string): string[] {
  if (!runScript) return [];
  const active = sanitizeShellLines(runScript);
  const m = /\bif\s+\[[^\]]+\];?\s*then\s*\n([^\n]+)\n\s*else\s*\n([^\n]+)\n\s*fi\b/.exec(runScript);
  if (m?.[1] && m[2]) { const a = sanitizeShellLines(m[1]); const b = sanitizeShellLines(m[2]); if (a.length > 0 && b.length > 0) active.push(...a, ...b); }
  return active;
}

function splitAndChainStrict(command: string): { parts: string[][]; error?: string } {
  const parts: string[][] = [];
  let curTokens: string[] = []; let cur = ""; let quote: "'" | '"' | null = null; let hasToken = false;
  for (let i = 0; i < command.length; i++) {
    const ch = command[i] ?? ""; const next = command[i + 1] ?? "";
    if (quote) {
      if (ch === quote && (quote === "'" || command[i - 1] !== "\\")) quote = null;
      else if (quote === '"' && (ch === "$" || ch === "`")) return { parts: [], error: "Command contains forbidden shell substitution inside quotes." };
      else cur += ch;
      continue;
    }
    if (ch === "'" || ch === '"') { quote = ch; hasToken = true; continue; }
    if (ch === "&" && next === "&") {
      if (hasToken || cur) { curTokens.push(cur); cur = ""; hasToken = false; }
      if (curTokens.length === 0) return { parts: [], error: "Empty segment around &&." };
      parts.push(curTokens); curTokens = []; i += 1; continue;
    }
    if (ch === "&" || SHELL_META_UNQUOTED.test(ch)) return { parts: [], error: `Command contains forbidden shell metacharacter '${ch}'.` };
    if (/\s/.test(ch)) { if (hasToken || cur) { curTokens.push(cur); cur = ""; hasToken = false; } continue; }
    cur += ch; hasToken = true;
  }
  if (quote) return { parts: [], error: "Unterminated quote in command." };
  if (hasToken || cur) curTokens.push(cur);
  if (curTokens.length > 0) parts.push(curTokens);
  return { parts };
}

function readPackageScripts(dir?: string): Record<string, string> {
  if (!dir) return {};
  const pkgPath = path.join(dir, "package.json");
  if (!fs.existsSync(pkgPath)) return {};
  try { const parsed = JSON.parse(fs.readFileSync(pkgPath, "utf8")) as { scripts?: Record<string, string> }; return parsed.scripts && typeof parsed.scripts === "object" ? parsed.scripts : {}; } catch { return {}; }
}

function isPathInsideRepo(candidate: string, repoRoot: string): boolean {
  const absRoot = (() => { try { return fs.realpathSync(path.resolve(repoRoot)); } catch { return path.resolve(repoRoot); } })();
  const raw = path.isAbsolute(candidate) ? path.resolve(candidate) : path.resolve(absRoot, candidate);
  let res = raw;
  try { res = fs.realpathSync(raw); } catch { try { res = path.join(fs.realpathSync(path.dirname(raw)), path.basename(raw)); } catch { res = raw; } }
  return res === absRoot || res.startsWith(`${absRoot}${path.sep}`);
}

function isOwnVeristackBin(repoRoot: string, relBin: string): boolean {
  try { return fs.realpathSync(path.join(repoRoot, relBin)) === fs.realpathSync(path.join(VERISTACK_ROOT_REALPATH, relBin)); } catch { return false; }
}

function unwrapPythonRunnerWrapper(cur: readonly string[], low0: string, repoRoot?: string): { next?: readonly string[]; error?: string } {
  let i = 2;
  while (i < cur.length && (cur[i] ?? "").startsWith("-")) {
    const fl = cur[i] ?? "";
    if (fl !== "--project" && fl !== "--directory") return { error: `wrapper flag '${fl}' is forbidden on ${low0} run` };
    const dirVal = cur[i + 1] ?? "";
    if (!dirVal || (repoRoot && !isPathInsideRepo(dirVal, repoRoot))) return { error: `wrapper flag '${fl}' path '${dirVal}' escapes repo root` };
    if (repoRoot) { const cfgErr = auditRunnerConfigs(repoRoot, [path.resolve(repoRoot, dirVal)]); if (cfgErr) return { error: cfgErr }; }
    i += 2;
  }
  const bin = (cur[i] ?? "").toLowerCase();
  if (!bin || bin.includes("/") || bin.includes("\\") || FORBIDDEN_VERBS.has(bin)) return { error: `disallowed ${low0} run target '${bin}'` };
  return { next: cur.slice(i) };
}

function unwrapPnpmFilter(cur: readonly string[], repoRoot?: string): { next?: readonly string[]; error?: string } {
  const rawF = cur[2] ?? "";
  const strippedF = rawF.replace(/^\.{3}|[\^]?\.{3}$/g, "");
  const f = /^\{(.+)\}$/.exec(strippedF)?.[1] ?? strippedF;
  if (repoRoot && (f.startsWith(".") || f.startsWith("/") || f.includes("..")) && !isPathInsideRepo(f, repoRoot)) return { error: `pnpm ${cur[1]} '${rawF}' escapes repo root` };
  if (repoRoot) { const cDir = path.resolve(repoRoot, f); if (fs.existsSync(cDir) && fs.statSync(cDir).isDirectory()) { const cfgErr = auditRunnerConfigs(repoRoot, [cDir]); if (cfgErr) return { error: cfgErr }; } }
  if ((cur[3] ?? "").toLowerCase() !== "exec" || !cur[4]) return { error: `pnpm ${cur[1]} requires 'exec <tool>' or an expanded workspace script` };
  return { next: cur.slice(4) };
}

export function extractToolHead(tokens: readonly string[], repoRoot?: string): { head: string; toolArgs: string[]; error?: string } {
  let cur = tokens;
  for (let hop = 0; hop < 8; hop++) {
    const t0 = cur[0] ?? "";
    if (!t0) return { head: "", toolArgs: [], error: "empty command" };
    if (/^[A-Za-z_]\w*=/.test(t0)) return { head: "", toolArgs: [], error: `env-variable override '${t0}' is forbidden` };
    if (t0.includes("/") || t0.includes("\\")) return { head: "", toolArgs: [], error: `path-qualified executable '${t0}' is forbidden` };
    const low0 = t0.toLowerCase();
    if (FORBIDDEN_VERBS.has(low0)) return { head: "", toolArgs: [], error: `forbidden no-op executable '${t0}'` };

    if (low0 === "npx" || low0 === "bunx") {
      let i = 1;
      while (i < cur.length && (cur[i] ?? "").startsWith("-")) {
        const fl = cur[i] ?? "";
        if (fl !== "--no-install" && fl !== "-y" && fl !== "--yes") return { head: "", toolArgs: [], error: `wrapper flag '${fl}' is forbidden on ${low0}` };
        i += 1;
      }
      const bin = (cur[i] ?? "").toLowerCase();
      if (!bin || bin.includes("/") || bin.includes("\\") || FORBIDDEN_VERBS.has(bin)) return { head: "", toolArgs: [], error: `disallowed ${low0} target '${bin}'` };
      return { head: bin, toolArgs: cur.slice(i + 1) };
    }
    if (low0 === "bun" && cur[1] === "--cwd" && cur[2] && cur[3]) {
      if (repoRoot && !isPathInsideRepo(cur[2], repoRoot)) return { head: "", toolArgs: [], error: `--cwd '${cur[2]}' escapes repo root` };
      if (cur[3].toLowerCase() === "test") return { head: "", toolArgs: [], error: "bun --cwd <dir> test invokes <dir>/package.json script 'test' (use 'bun test <dir>' or expand script)" };
      cur = [t0, ...cur.slice(3)]; continue;
    }
    if (low0 === "pnpm" && (cur[1] === "--filter" || cur[1] === "-F") && cur[2] && cur[3]) {
      const unwrapped = unwrapPnpmFilter(cur, repoRoot);
      if (unwrapped.error || !unwrapped.next) return { head: "", toolArgs: [], error: unwrapped.error ?? "invalid pnpm filter" };
      cur = unwrapped.next; continue;
    }
    if ((low0 === "pnpm" || low0 === "yarn") && (cur[1] ?? "").toLowerCase() === "exec") {
      const bin = (cur[2] ?? "").toLowerCase();
      if (!bin || bin.includes("/") || bin.includes("\\") || FORBIDDEN_VERBS.has(bin)) return { head: "", toolArgs: [], error: `disallowed exec target '${bin}'` };
      cur = cur.slice(2); continue;
    }
    if ((low0 === "uv" || low0 === "poetry" || low0 === "pipenv") && (cur[1] ?? "").toLowerCase() === "run") {
      const unwrapped = unwrapPythonRunnerWrapper(cur, low0, repoRoot);
      if (unwrapped.error || !unwrapped.next) return { head: "", toolArgs: [], error: unwrapped.error ?? "invalid wrapper" };
      cur = unwrapped.next; continue;
    }
    if ((low0 === "python" || low0 === "python3") && cur[1] === "-m" && cur[2]) return { head: cur[2].toLowerCase(), toolArgs: cur.slice(3) };
    if (low0 === "cargo" && (cur[1] ?? "").startsWith("+") && cur[2]) return { head: `cargo ${cur[2].toLowerCase()}`, toolArgs: cur.slice(3) };
    if (low0 === "node" || low0 === "bun" || low0 === "cargo" || low0 === "dotnet" || low0 === "go") {
      const sub = (cur[1] ?? "").toLowerCase();
      return { head: sub ? `${low0} ${sub}` : low0, toolArgs: cur.slice(2) };
    }
    return { head: low0, toolArgs: cur.slice(1) };
  }
  return { head: "", toolArgs: [], error: "command wrapper nesting exceeded cap" };
}

function validateDoubleDashArgs(mode: "clippy" | "cargo-test", tail: readonly string[]): string | null {
  if (mode === "clippy") {
    for (let i = 0; i < tail.length; i++) {
      const t = tail[i] ?? "";
      if (t === "-D" || t === "--deny" || t === "-W" || t === "--warn") {
        const lint = tail[i + 1]; if (!lint || lint.startsWith("-")) return `cargo clippy '${t}' requires a lint name`;
        i += 1; continue;
      }
      return `disallowed cargo clippy pass-through arg '${t}' (only -D/--deny and -W/--warn allowed)`;
    }
    return null;
  }
  for (let i = 0; i < tail.length; i++) {
    const t = tail[i] ?? "";
    if (t === "--nocapture" || t === "--show-output" || t.startsWith("--test-threads=")) continue;
    if (t === "--test-threads") { i += 1; continue; }
    return `disallowed cargo test pass-through arg '${t}'`;
  }
  return null;
}

const NUMERIC_FLAG_BOUNDS: ReadonlyArray<{ target: string; flag: string; check: (n: number) => boolean; msg: string }> = [
  { target: "go test", flag: "-count", check: (n) => n >= 1, msg: "go test -count must be >= 1" }, { target: "bun test", flag: "--rerun-each", check: (n) => n >= 1, msg: "bun test --rerun-each must be >= 1" },
  { target: "eslint", flag: "--max-warnings", check: (n) => n === 0, msg: "eslint --max-warnings must be 0" }, { target: "pytest", flag: "--cov-fail-under", check: (n) => n >= 1, msg: "pytest --cov-fail-under must be >= 1" },
  { target: "gremlins", flag: "--threshold-efficacy", check: (n) => n >= 75, msg: "gremlins --threshold-efficacy must be >= 75" }, { target: "vstack", flag: "--max-mutants", check: (n) => n >= 4, msg: "--max-mutants must be >= 4" },
  { target: "vstack", flag: "--min-kill-rate", check: (n) => n >= 0.75, msg: "--min-kill-rate must be >= 0.75" }, { target: "vstack", flag: "--max-crap", check: (n) => n > 0 && n <= 30, msg: "--max-crap must be in (0, 30]" },
  { target: "vstack", flag: "--max-time-exp", check: (n) => n > 0 && n <= 1.8, msg: "--max-time-exp must be in (0, 1.8]" },
];

function validateNumericFlagBound(head: string, schemaKey: string, flagName: string, val: string): string | null {
  const num = Number(val);
  for (const b of NUMERIC_FLAG_BOUNDS) if ((head === b.target || schemaKey === b.target) && flagName === b.flag && !b.check(num)) return `${b.msg} (got '${val}')`;
  return null;
}

interface CommandAuditCtx { rung: RungId | "canary"; repoRoot?: string; nestedCommandsOut?: string[]; }

function validateArgsWithPositiveSchema(head: string, toolArgs: readonly string[], ctx: CommandAuditCtx): string | null {
  const { rung, repoRoot, nestedCommandsOut } = ctx;
  const schemaKey = head === "node bin/vstack.mjs" || head === "bun src/cli.ts" ? "vstack" : head;
  const schema = RUNNER_SCHEMAS[schemaKey];
  if (!schema) {
    if (/^(?:bun|node)\s+\S+\.(?:test|spec)\.[cm]?[jt]sx?$/.test(head)) {
      const scriptPath = head.split(/\s+/)[1] ?? "";
      if (repoRoot && !isPathInsideRepo(scriptPath, repoRoot)) return `test path '${scriptPath}' escapes repo root`;
      return toolArgs.some((a) => a.startsWith("-")) ? `flags forbidden on direct test script '${head}'` : null;
    }
    if (/^(?:bun|node)\s+scripts\/check-(?:max-lines|perf-budget)\.mjs$/.test(head)) return toolArgs.some((a) => a.startsWith("-")) ? `flags forbidden on '${head}'` : null;
    for (const a of toolArgs) if (a.startsWith("-")) return `unrecognized flag '${a}' on '${head}'`;
    return null;
  }
  const isDotnet = head.startsWith("dotnet ");
  const repeatableFlags = s("--external", "--features", "--tags", "-D", "--reporter", "--reporters", "--test-reporter");
  const seenValueFlags = new Set<string>();
  const extraAuditDirs: string[] = [];
  for (let i = 0; i < toolArgs.length; i++) {
    const tok = toolArgs[i] ?? "";
    if (tok === "--") return schema.doubleDashMode ? validateDoubleDashArgs(schema.doubleDashMode, toolArgs.slice(i + 1)) : `argument separator '--' is forbidden on '${head}'`;
    if (!tok.startsWith("-")) {
      if (head === "hyperfine") { if (!nestedCommandsOut) return `nested hyperfine command '${tok}' is forbidden`; nestedCommandsOut.push(tok); continue; }
      const cleanTok = tok.split("::")[0]?.replace(/\/\.\.\.$/, "") ?? tok;
      if (repoRoot && (cleanTok.startsWith("/") || cleanTok.includes("..")) && !isPathInsideRepo(cleanTok, repoRoot)) return `positional path '${tok}' on '${head}' escapes repo root`;
      if (repoRoot && cleanTok && isPathInsideRepo(cleanTok, repoRoot)) { const rp = path.resolve(repoRoot, cleanTok); if (fs.existsSync(rp)) extraAuditDirs.push(fs.statSync(rp).isFile() ? path.dirname(rp) : rp); }
      continue;
    }
    const eqIdx = tok.indexOf("="); const colonIdx = isDotnet ? tok.indexOf(":") : -1;
    const sepIdx = eqIdx > 0 && (colonIdx < 0 || eqIdx < colonIdx) ? eqIdx : colonIdx;
    const flagName = sepIdx > 0 ? tok.slice(0, sepIdx) : tok;
    const inlineVal = sepIdx > 0 ? tok.slice(sepIdx + 1) : undefined;
    if (schema.boolFlags.has(tok) || (inlineVal === undefined && schema.boolFlags.has(flagName))) continue;
    if (!schema.valueFlags.has(flagName)) return `disallowed flag '${tok}' for '${head}' in ${rung} (positive flag allowlist)`;
    if (!repeatableFlags.has(flagName) && seenValueFlags.has(flagName)) return `duplicate value flag '${flagName}' on '${head}' is forbidden`;
    seenValueFlags.add(flagName);
    const val = inlineVal ?? toolArgs[i + 1];
    if (!val || (inlineVal === undefined && val.startsWith("-"))) return `flag '${flagName}' on '${head}' requires a value`;
    if (REPORTER_VALUE_FLAGS.has(flagName) && /^(?:vitest|jest|mocha|eslint|playwright|cypress|node --test|bun test)$/.test(head)) {
      const repParts = val.split(",").map((x) => x.trim().toLowerCase()).filter(Boolean);
      if (repParts.length === 0 || repParts.some((r) => !BUILTIN_REPORTERS.has(r))) return `disallowed reporter '${val}' on '${head}' (built-in reporters only)`;
    }
    if (PATH_VALUE_FLAGS.has(flagName) && !(isDotnet && (flagName === "-c" || flagName === "--configuration")) && !(head.startsWith("cargo ") && flagName === "-p") && !(head === "unittest" && flagName === "-p") && repoRoot && !isPathInsideRepo(val, repoRoot)) return `path flag '${flagName}=${val}' on '${head}' escapes repo root`;
    if (repoRoot && (flagName === "--manifest-path" || flagName === "--project" || flagName === "--directory" || flagName === "--cwd")) {
      const resolved = path.resolve(repoRoot, val);
      extraAuditDirs.push(fs.existsSync(resolved) && fs.statSync(resolved).isFile() ? path.dirname(resolved) : resolved);
    }
    const numErr = validateNumericFlagBound(head, schemaKey, flagName, val);
    if (numErr) return numErr;
    if (inlineVal === undefined) i += 1;
  }
  return repoRoot && extraAuditDirs.length > 0 ? auditRunnerConfigs(repoRoot, extraAuditDirs) : null;
}

function expandPackageScripts(command: string, repoRoot?: string): { steps: string[][]; cwds: string[]; error?: string } {
  const rootScripts = readPackageScripts(repoRoot);
  const out: string[][] = []; const cwds: string[] = [];
  const stack: Array<{ cmd: string; visiting: Set<string>; cwdDir?: string; hookName?: string }> = [{ cmd: command, visiting: new Set(), cwdDir: repoRoot }];
  for (let iter = 0; iter < 128 && stack.length > 0; iter++) {
    const item = stack.pop(); if (!item) break;
    const split = splitAndChainStrict(item.cmd.trim());
    if (split.error) return { steps: [], cwds: [], error: item.hookName ? `lifecycle hook '${item.hookName}': ${split.error}` : split.error };
    if (split.parts.length === 0) return { steps: [], cwds: [], error: "empty command" };
    const queued: Array<{ kind: "expand"; cmd: string; visiting: Set<string>; cwdDir?: string; hookName?: string } | { kind: "leaf"; seg: string[]; relCwd: string }> = [];
    for (const seg of split.parts) {
      const low0 = (seg[0] ?? "").toLowerCase(); const low1 = (seg[1] ?? "").toLowerCase();
      let scriptName: string | undefined; let extraArgs: string[] = [];
      let targetDir = item.cwdDir;
      let targetScripts = item.cwdDir === repoRoot ? rootScripts : readPackageScripts(item.cwdDir);
      if (low0 === "bun" && seg[1] === "--cwd" && seg[2] && seg[3]) {
        if (repoRoot && !isPathInsideRepo(seg[2], repoRoot)) return { steps: [], cwds: [], error: `--cwd '${seg[2]}' escapes repo root` };
        const subDir = repoRoot ? path.resolve(repoRoot, seg[2]) : seg[2];
        const subCfgErr = auditRunnerConfigs(repoRoot ?? subDir, [subDir]);
        if (subCfgErr) return { steps: [], cwds: [], error: subCfgErr };
        const subScripts = readPackageScripts(subDir); const subCmd = seg[3].toLowerCase();
        if (subCmd === "run" && seg[4]) { scriptName = seg[4]; extraArgs = seg.slice(5); targetDir = subDir; targetScripts = subScripts; }
        else if (subCmd === "test" && subScripts.test) { scriptName = "test"; extraArgs = seg.slice(4); targetDir = subDir; targetScripts = subScripts; }
      } else if ((low0 === "bun" || low0 === "npm" || low0 === "pnpm" || low0 === "yarn") && low1 === "run" && seg[2]) { scriptName = seg[2]; extraArgs = seg.slice(3); }
      else if ((low0 === "npm" || low0 === "pnpm" || low0 === "yarn") && low1 === "test") { scriptName = "test"; extraArgs = seg.slice(2); }
      else if ((low0 === "pnpm" || low0 === "yarn") && seg[1] && targetScripts[seg[1]]) { scriptName = seg[1]; extraArgs = seg.slice(2); }
      if (!scriptName) {
        const relCwd = repoRoot && targetDir && targetDir !== repoRoot ? path.relative(repoRoot, targetDir).split(path.sep).join("/") : "";
        queued.push({ kind: "leaf", seg, relCwd }); continue;
      }
      if (extraArgs.length > 0) return { steps: [], cwds: [], error: `trailing args on script '${scriptName}' are forbidden` };
      const body = targetScripts[scriptName];
      if (!body) return { steps: [], cwds: [], error: `unknown package.json script '${scriptName}'` };
      const visitKey = `${targetDir ?? ""}:${scriptName}`;
      if (item.visiting.has(visitKey)) return { steps: [], cwds: [], error: `cyclic package.json script '${scriptName}'` };
      const nextVisiting = new Set(item.visiting); nextVisiting.add(visitKey);
      for (const hook of [`pre${scriptName}`, scriptName, `post${scriptName}`]) {
        const hookBody = hook === scriptName ? body : targetScripts[hook];
        if (hookBody) queued.push({ kind: "expand", cmd: hookBody, visiting: nextVisiting, cwdDir: targetDir, hookName: hook === scriptName ? item.hookName : hook });
      }
    }
    if (queued.every((q) => q.kind === "leaf")) { for (const q of queued) if (q.kind === "leaf") { out.push(q.seg); cwds.push(q.relCwd); } continue; }
    for (let qi = queued.length - 1; qi >= 0; qi--) {
      const q = queued[qi]; if (!q) continue;
      if (q.kind === "expand") stack.push({ cmd: q.cmd, visiting: q.visiting, cwdDir: q.cwdDir, hookName: q.hookName });
      else stack.push({ cmd: q.seg.map((t) => (/\s/.test(t) ? `"${t}"` : t)).join(" "), visiting: item.visiting, cwdDir: q.relCwd && repoRoot ? path.resolve(repoRoot, q.relCwd) : repoRoot });
    }
  }
  return stack.length > 0 ? { steps: [], cwds: [], error: "package.json script expansion exceeded safety limit" } : { steps: out, cwds };
}

function validateExpandedCommandSteps(command: string, steps: readonly string[][], ctx: CommandAuditCtx): string | null {
  const { rung, repoRoot } = ctx;
  const allowed = ALLOWED_TOOL_PREFIXES[rung];
  let hasR1Typecheck = false;
  for (const seg of steps) {
    const { head, toolArgs, error } = extractToolHead(seg, repoRoot);
    if (error) return `Rung ${rung}: ${error}`;
    if (!allowed.some((re) => re.test(head))) return `Rung ${rung}: executable '${head}' is not an allowed ${rung} verification tool.`;
    if ((head === "node bin/vstack.mjs" || head === "bun src/cli.ts") && repoRoot && !isOwnVeristackBin(repoRoot, head === "node bin/vstack.mjs" ? "bin/vstack.mjs" : "src/cli.ts")) return `Rung ${rung}: local '${head}' is only allowed inside the veristack repository (binary realpath mismatch).`;
    const ownScriptMatch = /^(?:bun|node)\s+(scripts\/check-(?:max-lines|perf-budget)\.mjs)$/.exec(head);
    if (ownScriptMatch?.[1] && repoRoot && !isOwnVeristackBin(repoRoot, ownScriptMatch[1])) return `Rung ${rung}: '${head}' is only allowed inside the veristack repository (use 'vstack big-o', 'k6', 'hyperfine', etc.).`;
    const argErr = validateArgsWithPositiveSchema(head, toolArgs, ctx);
    if (argErr) return `Rung ${rung}: ${argErr}`;
    if (head === "vstack" || head === "node bin/vstack.mjs" || head === "bun src/cli.ts") {
      const sub = (toolArgs[0] ?? "").toLowerCase();
      if (!ALLOWED_VSTACK_BY_RUNG[rung].has(sub)) return `Rung ${rung}: disallowed vstack subcommand '${sub}' for ${rung}.`;
      if (VSTACK_REQUIRES_FAIL.has(sub) && !toolArgs.includes("--fail")) return `Rung ${rung}: vstack ${sub} must include --fail.`;
    }
    if (head === "pytest" && rung === "R6" && !toolArgs.includes("--benchmark-only") && !toolArgs.includes("--benchmark-enable")) return "Rung R6: pytest must run with --benchmark-only or --benchmark-enable.";
    if (head === "pytest" && rung !== "R6" && (toolArgs.includes("--benchmark-only") || toolArgs.includes("--benchmark-enable"))) return `Rung ${rung}: pytest --benchmark-only/--benchmark-enable is only allowed in R6.`;
    if (head === "dotnet test" && rung === "canary" && toolArgs.includes("--no-build")) return "Rung canary: dotnet test --no-build skips recompiling mutated/restored source.";
    if (rung === "R1" && /^(?:tsc|tsgo|mypy|pyright|basedpyright|cargo\s+(?:check|clippy)|dotnet\s+build|go\s+(?:vet|build))$/.test(head)) hasR1Typecheck = true;
  }
  return rung === "R1" && !hasR1Typecheck ? `Rung R1 command '${command}' must run a real typechecker/compiler.` : null;
}

export function parseAndValidateCommandArgv(rung: RungId | "canary", command: string, repoRoot?: string): { steps: string[][]; stepCwds?: string[]; error?: string } {
  if (repoRoot) { const cfgErr = auditRunnerConfigs(repoRoot); if (cfgErr) return { steps: [], error: `Rung ${rung}: ${cfgErr}` }; }
  const expanded = expandPackageScripts(command, repoRoot);
  if (expanded.error) return { steps: [], error: `Rung ${rung}: ${expanded.error}` };
  if (expanded.steps.length === 0) return { steps: [], error: `Rung ${rung}: command expands to zero executable steps.` };
  const nestedCommands: string[] = [];
  const stepErr = validateExpandedCommandSteps(command, expanded.steps, { rung, repoRoot, nestedCommandsOut: nestedCommands });
  if (stepErr) return { steps: [], error: stepErr };
  for (const nestedCmd of nestedCommands) {
    const nestedExp = expandPackageScripts(nestedCmd, repoRoot);
    if (nestedExp.error || nestedExp.steps.length === 0) return { steps: [], error: `Rung ${rung}: hyperfine command '${nestedCmd}' rejected: ${nestedExp.error ?? "empty command"}` };
    const nestedErr = validateExpandedCommandSteps(nestedCmd, nestedExp.steps, { rung, repoRoot });
    if (nestedErr) return { steps: [], error: `Rung ${rung}: hyperfine command '${nestedCmd}' rejected: ${nestedErr}` };
  }
  return { steps: expanded.steps, stepCwds: expanded.cwds };
}

export interface ArgvChainRunOptions { cwd: string; env: NodeJS.ProcessEnv; timeoutMs: number; stepCwds?: readonly string[]; }

export function runArgvChain(steps: readonly string[][], options: ArgvChainRunOptions): { status: number; stdout: string; stderr: string; signal: NodeJS.Signals | null; error?: Error } {
  const { cwd, env, timeoutMs, stepCwds } = options;
  if (steps.length === 0) return { status: 1, stdout: "", stderr: "empty argv chain", signal: null };
  let stdout = ""; let stderr = "";
  for (let idx = 0; idx < steps.length; idx++) {
    const argv = steps[idx] ?? []; const bin = argv[0] ?? "";
    if (!bin) return { status: 1, stdout, stderr: `${stderr}\nempty argv`, signal: null };
    const relSub = stepCwds?.[idx]; const resolvedSub = relSub ? path.resolve(cwd, relSub) : cwd;
    const res = spawnSync(bin, argv.slice(1), { cwd: relSub && fs.existsSync(resolvedSub) ? resolvedSub : cwd, shell: false, env, encoding: "utf8", timeout: timeoutMs, maxBuffer: 16 * 1024 * 1024 });
    stdout += res.stdout ?? ""; stderr += res.stderr ?? "";
    if (res.error || res.signal || res.status !== 0) return { status: res.status ?? 1, stdout, stderr, signal: res.signal ?? null, error: res.error };
  }
  return { status: 0, stdout, stderr, signal: null };
}

export function validateExecutableCommand(rung: RungId | "canary", command: string, repoRoot?: string): string | null {
  return parseAndValidateCommandArgv(rung, command, repoRoot).error ?? null;
}
