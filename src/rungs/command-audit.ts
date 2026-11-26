import { spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import type { RungId } from "../types.ts";

const SHELL_META_UNQUOTED = /[;|><$`(){}\n\r~]/;
const FORBIDDEN_VERBS = new Set([
  "echo", "printf", "true", "false", ":", "sleep", "exit", "exec", "eval", "alias",
  "source", ".", "diff", "kill", "trap", "env", "sh", "bash", "zsh", "cmd", "powershell",
]);

interface RunnerFlagSchema {
  boolFlags: ReadonlySet<string>;
  valueFlags: ReadonlySet<string>;
  allowDoubleDashPassThrough?: boolean;
}

const s = (...items: string[]): ReadonlySet<string> => new Set(items);

const RUNNER_SCHEMAS: Record<string, RunnerFlagSchema> = {
  oxlint: { boolFlags: s("--deny-warnings", "--quiet", "--fix-suggestions"), valueFlags: s("-c", "--config", "-f", "--format") },
  oxfmt: { boolFlags: s("--check"), valueFlags: s("-c", "--config") },
  eslint: { boolFlags: s("--quiet", "--no-warn-ignored"), valueFlags: s("-c", "--config", "--max-warnings", "--ext", "-f", "--format") },
  prettier: { boolFlags: s("--check", "-c"), valueFlags: s("--config", "--ignore-path") },
  biome: { boolFlags: s("--error-on-warnings"), valueFlags: s("--config-path", "--reporter") },
  ruff: { boolFlags: s("check", "format", "--check", "--diff", "--no-fix", "--quiet"), valueFlags: s("--config", "--output-format") },
  "golangci-lint": { boolFlags: s("run", "--fast"), valueFlags: s("-c", "--config", "--timeout") },
  gofmt: { boolFlags: s("-l", "-d", "-s"), valueFlags: s() },
  goimports: { boolFlags: s("-l", "-d"), valueFlags: s() },
  dprint: { boolFlags: s("check"), valueFlags: s("-c", "--config") },
  stylua: { boolFlags: s("--check"), valueFlags: s("-f", "--config-path") },
  rubocop: { boolFlags: s("--fail-fast"), valueFlags: s("-c", "--config", "-f", "--format") },
  ktlint: { boolFlags: s(), valueFlags: s("--reporter") },
  checkstyle: { boolFlags: s(), valueFlags: s("-c") },
  tsc: { boolFlags: s("--noEmit", "--strict", "--pretty", "--incremental", "--composite"), valueFlags: s("-p", "--project") },
  tsgo: { boolFlags: s("--noEmit", "--strict", "--pretty"), valueFlags: s("-p", "--project") },
  mypy: { boolFlags: s("--strict", "--no-error-summary", "--show-error-codes"), valueFlags: s("--config-file", "--python-version") },
  pyright: { boolFlags: s("--warnings", "--stats"), valueFlags: s("-p", "--project", "--pythonversion") },
  basedpyright: { boolFlags: s("--warnings", "--stats"), valueFlags: s("-p", "--project") },
  knip: { boolFlags: s("--no-progress", "--strict"), valueFlags: s("-c", "--config", "-W", "--workspace") },
  "deslop-please": { boolFlags: s("--strict", "--json"), valueFlags: s("-c", "--config") },
  vulture: { boolFlags: s(), valueFlags: s("--min-confidence") },
  deadcode: { boolFlags: s("-test"), valueFlags: s() },
  staticcheck: { boolFlags: s(), valueFlags: s("-checks", "-f") },
  "import-linter": { boolFlags: s(), valueFlags: s("--config") },
  vitest: { boolFlags: s("run", "--run", "--coverage", "--bail"), valueFlags: s("--reporter", "--outputFile", "--testTimeout", "--project") },
  jest: { boolFlags: s("--ci", "--coverage", "--bail", "--runInBand", "--no-cache"), valueFlags: s("--reporters", "--testTimeout") },
  mocha: { boolFlags: s("--bail", "--recursive"), valueFlags: s("--reporter", "--timeout") },
  ava: { boolFlags: s("--fail-fast", "--verbose"), valueFlags: s("--timeout") },
  pytest: { boolFlags: s("-q", "-v", "-vv", "-x", "--strict-markers", "--benchmark-only", "--benchmark-enable"), valueFlags: s("-m", "--junitxml", "--cov", "--cov-report", "--tb", "--timeout", "--maxfail", "--benchmark-min-rounds") },
  phpunit: { boolFlags: s("--stop-on-failure"), valueFlags: s("--log-junit") },
  rspec: { boolFlags: s("--fail-fast"), valueFlags: s("-f", "--format", "-o", "--out") },
  unittest: { boolFlags: s("discover", "-v", "-f"), valueFlags: s("-s", "-p", "-t") },
  "bun test": { boolFlags: s("--bail", "--coverage", "--rerun-each"), valueFlags: s("--timeout", "--reporter", "--reporter-outfile", "--concurrency") },
  "bun build": { boolFlags: s("--minify", "--sourcemap"), valueFlags: s("--outfile", "--outdir", "--target", "--external", "--format") },
  "node --test": { boolFlags: s("--experimental-test-coverage"), valueFlags: s("--test-reporter", "--test-reporter-destination", "--test-timeout") },
  "dotnet build": { boolFlags: s("--warnaserror", "--no-restore", "-warnaserror"), valueFlags: s("-c", "--configuration", "-v", "--verbosity") },
  "dotnet format": { boolFlags: s("--verify-no-changes", "--no-restore"), valueFlags: s("-v", "--verbosity") },
  "dotnet test": { boolFlags: s("--no-build", "--no-restore", "--collect"), valueFlags: s("-c", "--configuration", "-v", "--verbosity", "--logger", "--results-directory") },
  "dotnet stryker": { boolFlags: s(), valueFlags: s("-p", "--project", "-r", "--reporter", "-o", "--output") },
  "dotnet run": { boolFlags: s("--no-build", "-c"), valueFlags: s("-c", "--configuration", "--project") },
  "cargo fmt": { boolFlags: s("--check", "--all"), valueFlags: s("--manifest-path") },
  "cargo clippy": { boolFlags: s("--all-targets", "--all-features", "--workspace", "--locked"), valueFlags: s("--manifest-path", "-p", "--package"), allowDoubleDashPassThrough: true },
  "cargo check": { boolFlags: s("--all-targets", "--all-features", "--workspace", "--locked"), valueFlags: s("--manifest-path", "-p", "--package") },
  "cargo test": { boolFlags: s("--all-targets", "--all-features", "--workspace", "--locked", "--lib", "--bins", "--tests", "--doc"), valueFlags: s("--manifest-path", "-p", "--package", "--test") },
  "cargo nextest": { boolFlags: s("run", "--all-features", "--workspace", "--locked"), valueFlags: s("--manifest-path", "-p", "--package", "--profile") },
  "cargo bench": { boolFlags: s("--all-features", "--workspace", "--locked"), valueFlags: s("--manifest-path", "-p", "--package", "--bench") },
  "cargo mutants": { boolFlags: s("--workspace", "--in-place"), valueFlags: s("--manifest-path", "-p", "--package", "-j", "--jobs", "--timeout") },
  "cargo deny": { boolFlags: s("check"), valueFlags: s("--manifest-path") },
  "cargo machete": { boolFlags: s("--with-metadata"), valueFlags: s() },
  "cargo udeps": { boolFlags: s("--all-targets"), valueFlags: s("--manifest-path") },
  "go vet": { boolFlags: s(), valueFlags: s() },
  "go build": { boolFlags: s("-race"), valueFlags: s("-o") },
  "go test": { boolFlags: s("-v", "-race", "-count=1", "-short"), valueFlags: s("-count", "-timeout", "-coverprofile", "-covermode", "-fuzz", "-fuzztime", "-bench", "-benchmem", "-benchtime") },
  stryker: { boolFlags: s("run"), valueFlags: s("--reporters", "--concurrency", "--mutate") },
  mutmut: { boolFlags: s("run", "results"), valueFlags: s("--paths-to-mutate", "--tests-dir") },
  gremlins: { boolFlags: s("unleash"), valueFlags: s("--threshold-efficacy", "--tags") },
  bend: { boolFlags: s("--verdict", "--check-only"), valueFlags: s() },
  quint: { boolFlags: s("verify", "run", "typecheck"), valueFlags: s("--invariant", "--max-steps", "--max-samples") },
  dafny: { boolFlags: s("verify"), valueFlags: s("--verification-time-limit") },
  kani: { boolFlags: s("--tests"), valueFlags: s("--manifest-path", "--harness") },
  playwright: { boolFlags: s("test"), valueFlags: s("--project", "--reporter", "--workers", "--timeout") },
  cypress: { boolFlags: s("run"), valueFlags: s("--browser", "--spec", "--reporter") },
  k6: { boolFlags: s("run"), valueFlags: s("--vus", "--duration", "--out", "--summary-export") },
  hyperfine: { boolFlags: s("--warmup"), valueFlags: s("--warmup", "--runs", "--min-runs", "--export-json") },
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

const ALLOWED_VSTACK_SUBCMDS = s(
  "scan", "verify", "run-rung", "canary", "perimeter", "crap", "oracle-check",
  "no-comments", "state-machines", "diff-cheats", "formal-sync", "laws", "bench", "big-o", "spc",
);
const VSTACK_REQUIRES_FAIL = s("canary", "formal-sync", "laws", "bench", "no-comments", "state-machines", "perimeter", "crap", "diff-cheats", "big-o", "spc");

export function scrubChildEnv(baseEnv: NodeJS.ProcessEnv = process.env): NodeJS.ProcessEnv {
  const clean: NodeJS.ProcessEnv = {};
  for (const [k, v] of Object.entries(baseEnv)) {
    if (v === undefined) continue;
    if (k === "VSTACK_RECEIPT_KEY" || k.startsWith("VSTACK_") || k === "GITHUB_TOKEN" || k === "GH_TOKEN" || k === "NPM_TOKEN" || k === "NODE_AUTH_TOKEN" || k.startsWith("ACTIONS_ID_TOKEN_") || k === "ACTIONS_RUNTIME_TOKEN") continue;
    clean[k] = v;
  }
  return clean;
}

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
    const trimmedEnd = raw.replace(/\s+$/, "");
    if (trimmedEnd.endsWith("\\")) buf += `${trimmedEnd.slice(0, -1)} `;
    else { joined.push(buf + raw); buf = ""; }
  }
  if (buf) joined.push(buf);
  return joined;
}

export function sanitizeShellBlock(runScript: string): string[] {
  const active: string[] = [];
  let setPlusE = false; let pipefail = false; let heredocEnd: string | null = null;
  let inFunction = false; let braceDepth = 0; let ifDepth = 0; let loopDepth = 0; let caseDepth = 0;

  for (const raw of joinLineContinuations(runScript)) {
    const trimmedRaw = raw.trim();
    if (heredocEnd !== null) {
      if (trimmedRaw === heredocEnd) heredocEnd = null;
      continue;
    }
    const hdMatch = /<<-?\s*['"]?([A-Za-z0-9_]+)['"]?/.exec(raw);
    if (hdMatch?.[1]) { heredocEnd = hdMatch[1]; continue; }

    const trimmed = stripShellComment(raw).trim();
    if (!trimmed) continue;

    if (inFunction) {
      braceDepth += (trimmed.match(/\{/g) ?? []).length - (trimmed.match(/\}/g) ?? []).length;
      if (braceDepth <= 0) { inFunction = false; braceDepth = 0; }
      continue;
    }
    if (/^(?:function\s+[A-Za-z_]\w*|[A-Za-z_]\w*\s*\(\s*\))\s*\{?/.test(trimmed)) {
      inFunction = true;
      braceDepth = (trimmed.match(/\{/g) ?? []).length - (trimmed.match(/\}/g) ?? []).length;
      if (braceDepth <= 0 && trimmed.includes("}")) inFunction = false;
      continue;
    }

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

    if (/^(?:elif\s+|else\b|then\b|alias\s+|\$\{\{|!(\s|$)|[A-Za-z0-9_*?|]+\))/.test(trimmed)) continue;
    if (/^(?:echo|printf|true|sleep)(?:\s|;|$)/.test(trimmed)) continue;
    if (/^:(?:\s|;|$)/.test(trimmed)) continue;
    if (/^false(?:\s|&&|\|\||;|$)/.test(trimmed)) continue;
    if (/^\.\/vstack\b/.test(trimmed)) continue;
    if (/\|\|/.test(trimmed)) continue;
    if (/;\s*(?:true|echo|printf|:|exit)(?:\s|$)/.test(trimmed)) continue;
    if (/(?:^|[^&])&\s*$/.test(trimmed)) continue;
    if (/&&\s*(?:echo|printf|true|:)(?:\s|$)/.test(trimmed)) continue;
    if (!pipefail && /\|\s*(?:tee|cat|true|head|tail|grep|awk|sed)\b/.test(trimmed)) continue;
    if (/\s(?:--help|-h|--version|-V|--list-tests)(?:\s|$)/.test(trimmed)) continue;
    active.push(trimmed);
  }
  return active;
}

function splitAndChainStrict(command: string): { parts: string[][]; error?: string } {
  const parts: string[][] = [];
  let curTokens: string[] = [];
  let cur = "";
  let quote: "'" | '"' | null = null;
  let hasToken = false;

  for (let i = 0; i < command.length; i++) {
    const ch = command[i] ?? "";
    const next = command[i + 1] ?? "";
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
      parts.push(curTokens);
      curTokens = [];
      i += 1;
      continue;
    }
    if (ch === "&" || SHELL_META_UNQUOTED.test(ch)) return { parts: [], error: `Command contains forbidden shell metacharacter '${ch}'.` };
    if (/\s/.test(ch)) {
      if (hasToken || cur) { curTokens.push(cur); cur = ""; hasToken = false; }
      continue;
    }
    cur += ch;
    hasToken = true;
  }
  if (quote) return { parts: [], error: "Unterminated quote in command." };
  if (hasToken || cur) curTokens.push(cur);
  if (curTokens.length > 0) parts.push(curTokens);
  return { parts };
}

function readPackageJson(repoRoot?: string): { name?: string; scripts: Record<string, string> } {
  if (!repoRoot) return { scripts: {} };
  const pkgPath = path.join(repoRoot, "package.json");
  if (!fs.existsSync(pkgPath)) return { scripts: {} };
  try {
    const parsed = JSON.parse(fs.readFileSync(pkgPath, "utf8")) as { name?: string; scripts?: Record<string, string> };
    return { name: parsed.name, scripts: parsed.scripts && typeof parsed.scripts === "object" ? parsed.scripts : {} };
  } catch {
    return { scripts: {} };
  }
}

function extractToolHead(tokens: readonly string[]): { head: string; toolArgs: string[]; error?: string } {
  const t0 = tokens[0] ?? "";
  if (!t0) return { head: "", toolArgs: [], error: "empty command" };
  if (/^[A-Za-z_]\w*=/.test(t0)) return { head: "", toolArgs: [], error: `env-variable override '${t0}' is forbidden` };
  if (t0.includes("/") || t0.includes("\\")) return { head: "", toolArgs: [], error: `path-qualified executable '${t0}' is forbidden` };
  const low0 = t0.toLowerCase();
  if (FORBIDDEN_VERBS.has(low0)) return { head: "", toolArgs: [], error: `forbidden no-op executable '${t0}'` };

  if (low0 === "npx" || low0 === "bunx") {
    let i = 1;
    while (i < tokens.length && (tokens[i] ?? "").startsWith("-")) {
      const fl = tokens[i] ?? "";
      if (fl !== "--no-install" && fl !== "-y" && fl !== "--yes") {
        return { head: "", toolArgs: [], error: `wrapper flag '${fl}' is forbidden on ${low0}` };
      }
      i += 1;
    }
    const bin = (tokens[i] ?? "").toLowerCase();
    if (!bin || bin.includes("/") || bin.includes("\\") || FORBIDDEN_VERBS.has(bin)) {
      return { head: "", toolArgs: [], error: `disallowed ${low0} target '${bin}'` };
    }
    return { head: bin, toolArgs: tokens.slice(i + 1) };
  }
  if ((low0 === "pnpm" || low0 === "yarn") && (tokens[1] ?? "").toLowerCase() === "exec") {
    const bin = (tokens[2] ?? "").toLowerCase();
    if (!bin || bin.includes("/") || bin.includes("\\") || FORBIDDEN_VERBS.has(bin)) {
      return { head: "", toolArgs: [], error: `disallowed exec target '${bin}'` };
    }
    return { head: bin, toolArgs: tokens.slice(3) };
  }
  if ((low0 === "uv" || low0 === "poetry" || low0 === "pipenv") && (tokens[1] ?? "").toLowerCase() === "run") {
    let i = 2;
    while (i < tokens.length && (tokens[i] ?? "").startsWith("-")) {
      const fl = tokens[i] ?? "";
      if (fl === "--project" || fl === "--directory") { i += 2; continue; }
      return { head: "", toolArgs: [], error: `wrapper flag '${fl}' is forbidden on ${low0} run` };
    }
    const bin = (tokens[i] ?? "").toLowerCase();
    if (!bin || bin.includes("/") || bin.includes("\\") || FORBIDDEN_VERBS.has(bin)) {
      return { head: "", toolArgs: [], error: `disallowed ${low0} run target '${bin}'` };
    }
    return { head: bin, toolArgs: tokens.slice(i + 1) };
  }
  if ((low0 === "python" || low0 === "python3") && tokens[1] === "-m" && tokens[2]) {
    return { head: tokens[2].toLowerCase(), toolArgs: tokens.slice(3) };
  }
  if (low0 === "cargo" && (tokens[1] ?? "").startsWith("+") && tokens[2]) {
    return { head: `cargo ${tokens[2].toLowerCase()}`, toolArgs: tokens.slice(3) };
  }
  if (low0 === "node" || low0 === "bun" || low0 === "cargo" || low0 === "dotnet" || low0 === "go") {
    const sub = (tokens[1] ?? "").toLowerCase();
    return { head: sub ? `${low0} ${sub}` : low0, toolArgs: tokens.slice(2) };
  }
  return { head: low0, toolArgs: tokens.slice(1) };
}

function validateArgsWithPositiveSchema(head: string, toolArgs: readonly string[], rung: RungId | "canary"): string | null {
  const schemaKey = head === "node bin/vstack.mjs" || head === "bun src/cli.ts" ? "vstack" : head;
  const schema = RUNNER_SCHEMAS[schemaKey];
  if (!schema) {
    if (/^(?:bun|node)\s+\S+\.(?:test|spec)\.[cm]?[jt]sx?$/.test(head)) {
      return toolArgs.some((a) => a.startsWith("-")) ? `flags forbidden on direct test script '${head}'` : null;
    }
    if (/^(?:bun|node)\s+scripts\/check-(?:max-lines|perf-budget)\.mjs$/.test(head)) {
      return toolArgs.some((a) => a.startsWith("-")) ? `flags forbidden on '${head}'` : null;
    }
    for (const a of toolArgs) {
      if (a.startsWith("-")) return `unrecognized flag '${a}' on '${head}'`;
    }
    return null;
  }

  for (let i = 0; i < toolArgs.length; i++) {
    const tok = toolArgs[i] ?? "";
    if (tok === "--") {
      if (schema.allowDoubleDashPassThrough) return null;
      return `argument separator '--' is forbidden on '${head}'`;
    }
    if (!tok.startsWith("-")) continue;
    const eqIdx = tok.indexOf("=");
    const flagName = eqIdx > 0 ? tok.slice(0, eqIdx) : tok;
    const inlineVal = eqIdx > 0 ? tok.slice(eqIdx + 1) : undefined;
    if (schema.boolFlags.has(tok) || (inlineVal === undefined && schema.boolFlags.has(flagName))) continue;
    if (schema.valueFlags.has(flagName)) {
      const val = inlineVal ?? toolArgs[i + 1];
      if (!val || (inlineVal === undefined && val.startsWith("-"))) return `flag '${flagName}' on '${head}' requires a value`;
      if (head === "node --test" && flagName === "--test-reporter" && !/^(?:spec|tap|dot|junit|lcov)$/.test(val)) {
        return `disallowed --test-reporter '${val}' (built-in reporters only)`;
      }
      if (schemaKey === "vstack" && flagName === "--min-kill-rate" && !(Number(val) >= 0.75)) {
        return `--min-kill-rate must be >= 0.75 (got '${val}')`;
      }
      if (inlineVal === undefined) i += 1;
      continue;
    }
    return `disallowed flag '${tok}' for '${head}' in ${rung} (positive flag allowlist)`;
  }
  return null;
}

export function parseAndValidateCommandArgv(
  rung: RungId | "canary",
  command: string,
  repoRoot?: string,
): { steps: string[][]; error?: string } {
  if (repoRoot) {
    const bunfig = path.join(repoRoot, "bunfig.toml");
    if (fs.existsSync(bunfig)) {
      try {
        if (/\bpreload\s*=/.test(fs.readFileSync(bunfig, "utf8"))) {
          return { steps: [], error: `Rung ${rung}: bunfig.toml declares 'preload', which can intercept test runners.` };
        }
      } catch {
        return { steps: [], error: `Rung ${rung}: unreadable bunfig.toml.` };
      }
    }
  }

  const pkg = readPackageJson(repoRoot);
  const scripts = pkg.scripts;
  const expand = (cmd: string, visiting: Set<string>): { steps: string[][]; error?: string } => {
    const split = splitAndChainStrict(cmd.trim());
    if (split.error) return { steps: [], error: split.error };
    if (split.parts.length === 0) return { steps: [], error: "empty command" };

    const out: string[][] = [];
    for (const seg of split.parts) {
      const low0 = (seg[0] ?? "").toLowerCase();
      const low1 = (seg[1] ?? "").toLowerCase();
      let scriptName: string | undefined;
      let extraArgs: string[] = [];
      if ((low0 === "bun" || low0 === "npm" || low0 === "pnpm" || low0 === "yarn") && low1 === "run" && seg[2]) {
        scriptName = seg[2];
        extraArgs = seg.slice(3);
      } else if ((low0 === "npm" || low0 === "pnpm" || low0 === "yarn") && low1 === "test") {
        scriptName = "test";
        extraArgs = seg.slice(2);
      } else if ((low0 === "pnpm" || low0 === "yarn") && seg[1] && scripts[seg[1]]) {
        scriptName = seg[1];
        extraArgs = seg.slice(2);
      }

      if (scriptName) {
        if (extraArgs.length > 0) return { steps: [], error: `trailing args on script '${scriptName}' are forbidden` };
        const body = scripts[scriptName];
        if (!body) return { steps: [], error: `unknown package.json script '${scriptName}'` };
        if (visiting.has(scriptName)) return { steps: [], error: `cyclic package.json script '${scriptName}'` };
        const nextVisiting = new Set(visiting);
        nextVisiting.add(scriptName);
        const preBody = scripts[`pre${scriptName}`];
        if (preBody) {
          const preRes = expand(preBody, nextVisiting);
          if (preRes.error) return { steps: [], error: `lifecycle hook 'pre${scriptName}': ${preRes.error}` };
          out.push(...preRes.steps);
        }
        const sub = expand(body, nextVisiting);
        if (sub.error) return sub;
        out.push(...sub.steps);
        const postBody = scripts[`post${scriptName}`];
        if (postBody) {
          const postRes = expand(postBody, nextVisiting);
          if (postRes.error) return { steps: [], error: `lifecycle hook 'post${scriptName}': ${postRes.error}` };
          out.push(...postRes.steps);
        }
      } else {
        out.push(seg);
      }
    }
    return { steps: out };
  };

  const expanded = expand(command, new Set());
  if (expanded.error) return { steps: [], error: `Rung ${rung}: ${expanded.error}` };
  if (expanded.steps.length === 0) return { steps: [], error: `Rung ${rung}: command expands to zero executable steps.` };

  const allowed = ALLOWED_TOOL_PREFIXES[rung];
  let hasR1Typecheck = false;

  for (const seg of expanded.steps) {
    const { head, toolArgs, error } = extractToolHead(seg);
    if (error) return { steps: [], error: `Rung ${rung}: ${error}` };
    if (!allowed.some((re) => re.test(head))) {
      return { steps: [], error: `Rung ${rung}: executable '${head}' is not an allowed ${rung} verification tool.` };
    }
    if ((head === "node bin/vstack.mjs" || head === "bun src/cli.ts") && repoRoot && pkg.name !== "veristack") {
      return { steps: [], error: `Rung ${rung}: local '${head}' is only allowed inside the veristack repository itself.` };
    }
    const argErr = validateArgsWithPositiveSchema(head, toolArgs, rung);
    if (argErr) return { steps: [], error: `Rung ${rung}: ${argErr}` };

    if (head === "vstack" || head === "node bin/vstack.mjs" || head === "bun src/cli.ts") {
      const sub = (toolArgs[0] ?? "").toLowerCase();
      if (!ALLOWED_VSTACK_SUBCMDS.has(sub)) return { steps: [], error: `Rung ${rung}: disallowed vstack subcommand '${sub}'.` };
      if (VSTACK_REQUIRES_FAIL.has(sub) && !toolArgs.includes("--fail")) {
        return { steps: [], error: `Rung ${rung}: vstack ${sub} must include --fail.` };
      }
    }
    if (head === "pytest" && rung === "R6" && !toolArgs.includes("--benchmark-only") && !toolArgs.includes("--benchmark-enable")) {
      return { steps: [], error: "Rung R6: pytest must run with --benchmark-only or --benchmark-enable." };
    }
    if (head === "bun scripts/check-perf-budget.mjs" || head === "node scripts/check-perf-budget.mjs") {
      if (repoRoot) {
        const absScript = path.join(repoRoot, "scripts/check-perf-budget.mjs");
        if (fs.existsSync(absScript) && !/\b(?:performance\.now|hrtime|fitEmpiricalBigO)\b/.test(fs.readFileSync(absScript, "utf8"))) {
          return { steps: [], error: `Rung ${rung}: scripts/check-perf-budget.mjs lacks real timing measurement.` };
        }
      }
    }
    if (rung === "R1" && /^(?:tsc|tsgo|mypy|pyright|basedpyright|cargo\s+(?:check|clippy)|dotnet\s+build|go\s+(?:vet|build))$/.test(head)) {
      hasR1Typecheck = true;
    }
  }

  if (rung === "R1" && !hasR1Typecheck) {
    return { steps: [], error: `Rung R1 command '${command}' must run a real typechecker/compiler.` };
  }
  return { steps: expanded.steps };
}

export function runArgvChain(
  steps: readonly string[][],
  cwd: string,
  env: NodeJS.ProcessEnv,
  timeoutMs: number,
): { status: number; stdout: string; stderr: string; signal: NodeJS.Signals | null; error?: Error } {
  if (steps.length === 0) return { status: 1, stdout: "", stderr: "empty argv chain", signal: null };
  let stdout = "";
  let stderr = "";
  for (const argv of steps) {
    const bin = argv[0] ?? "";
    if (!bin) return { status: 1, stdout, stderr: `${stderr}\nempty argv`, signal: null };
    const res = spawnSync(bin, argv.slice(1), { cwd, shell: false, env, encoding: "utf8", timeout: timeoutMs, maxBuffer: 16 * 1024 * 1024 });
    stdout += res.stdout ?? "";
    stderr += res.stderr ?? "";
    if (res.error || res.signal || res.status !== 0) {
      return { status: res.status ?? 1, stdout, stderr, signal: res.signal ?? null, error: res.error };
    }
  }
  return { status: 0, stdout, stderr, signal: null };
}

export function validateExecutableCommand(rung: RungId | "canary", command: string, repoRoot?: string): string | null {
  return parseAndValidateCommandArgv(rung, command, repoRoot).error ?? null;
}
