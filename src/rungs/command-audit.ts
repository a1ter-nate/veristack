import { spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import type { RungId } from "../types.ts";

const SHELL_META_UNQUOTED = /[;|><$`(){}\n\r~]/;
const FORBIDDEN_ENV_PREFIX = /^(?:PATH|NODE_OPTIONS|PYTHONPATH|LD_PRELOAD|DYLD_INSERT_LIBRARIES|BASH_ENV|ENV|IFS|BUN_CONFIG_PATH|RUBYOPT|PERL5OPT)=/i;
const FORBIDDEN_FLAGS_EXACT = new Set([
  "--version", "-V", "--help", "-h", "--list", "--list-tests", "--co", "--collect-only", "--no-run",
  "--passWithNoTests", "--showConfig", "--rules", "--noCheck", "--preload", "-A", "--eval", "--print",
]);
const FORBIDDEN_VERBS = new Set([
  "echo", "printf", "true", "false", ":", "sleep", "exit", "exec", "eval", "alias",
  "source", ".", "diff", "kill", "trap", "env", "sh", "bash", "zsh", "cmd", "powershell",
]);

const ALLOWED_TOOL_PREFIXES: Record<RungId | "canary", readonly RegExp[]> = {
  R0: [
    /^(?:oxlint|oxfmt|eslint|prettier|biome|ruff|golangci-lint|gofmt|goimports|vstack|dprint|stylua|rubocop|ktlint|checkstyle)$/,
    /^(?:cargo\s+(?:fmt|clippy)|dotnet\s+(?:format|build)|node\s+bin\/vstack\.mjs|bun\s+src\/cli\.ts)$/,
  ],
  R1: [
    /^(?:tsc|tsgo|mypy|pyright|basedpyright|knip|deslop-please|vulture|deadcode|staticcheck|import-linter)$/,
    /^(?:cargo\s+(?:check|clippy|udeps|machete|deny)|dotnet\s+build|go\s+(?:vet|build)|bun\s+build|node\s+scripts\/check-max-lines\.mjs|bun\s+scripts\/check-max-lines\.mjs)$/,
  ],
  R2: [
    /^(?:vitest|jest|mocha|ava|pytest|phpunit|rspec|xunit|nunit|ctest|unittest)$/,
    /^(?:bun\s+test|node\s+--test|dotnet\s+test|cargo\s+(?:test|nextest)|go\s+test)$/,
  ],
  R3: [
    /^(?:vitest|jest|pytest|pact|pact-go|storybook|schemathesis)$/,
    /^(?:bun\s+test|node\s+--test|dotnet\s+test|cargo\s+(?:test|nextest)|go\s+test)$/,
  ],
  R4: [
    /^(?:vitest|jest|pytest|prisma|alembic|flyway|goose|golang-migrate|drizzle-kit)$/,
    /^(?:bun\s+test|node\s+--test|dotnet\s+test|cargo\s+(?:test|nextest)|go\s+test)$/,
  ],
  R5: [
    /^(?:stryker|mutmut|pitest|gremlins|go-mutesting|crosshair|bend|quint|dafny|kani|stateright|chromatic|percy|argos|bombadil|vstack|pytest)$/,
    /^(?:cargo\s+(?:mutants|test|nextest)|dotnet\s+(?:stryker|test)|go\s+test|node\s+bin\/vstack\.mjs|bun\s+src\/cli\.ts)$/,
  ],
  R6: [
    /^(?:k6|lighthouse|lhci|locust|mitata|tinybench|divan|nbomber|hyperfine|criterion|vstack|pytest)$/,
    /^(?:cargo\s+bench|go\s+test|dotnet\s+run|node\s+bin\/vstack\.mjs|bun\s+src\/cli\.ts|bun\s+scripts\/check-perf-budget\.mjs|node\s+scripts\/check-perf-budget\.mjs)$/,
  ],
  R7: [
    /^(?:playwright|cypress|maestro|detox|webdriverio|wdio|pytest)$/,
    /^(?:go\s+test|cargo\s+(?:test|nextest)|dotnet\s+test|bun\s+test)$/,
  ],
  R8: [/^(?:k6|playwright|curl|synthetic|canary|smoke-prod|healthcheck)$/],
  canary: [
    /^(?:vitest|jest|mocha|ava|pytest|phpunit|rspec|xunit|nunit|ctest|unittest)$/,
    /^(?:bun\s+test|node\s+--test|dotnet\s+test|cargo\s+(?:test|nextest)|go\s+test|(?:bun|node)\s+\S+\.(?:test|spec)\.[cm]?[jt]sx?)$/,
  ],
};

const ALLOWED_VSTACK_SUBCMDS = new Set([
  "scan", "verify", "run-rung", "canary", "perimeter", "crap", "oracle-check",
  "no-comments", "state-machines", "diff-cheats", "formal-sync", "laws", "bench", "big-o", "spc",
]);

export function scrubChildEnv(baseEnv: NodeJS.ProcessEnv = process.env): NodeJS.ProcessEnv {
  const clean: NodeJS.ProcessEnv = {};
  for (const [k, v] of Object.entries(baseEnv)) {
    if (v === undefined) continue;
    if (
      k === "VSTACK_RECEIPT_KEY" ||
      k.startsWith("VSTACK_") ||
      k === "GITHUB_TOKEN" ||
      k === "GH_TOKEN" ||
      k === "NPM_TOKEN" ||
      k === "NODE_AUTH_TOKEN" ||
      k.startsWith("ACTIONS_ID_TOKEN_") ||
      k === "ACTIONS_RUNTIME_TOKEN"
    ) {
      continue;
    }
    clean[k] = v;
  }
  return clean;
}

function stripShellComment(line: string): string {
  let inSingle = false;
  let inDouble = false;
  for (let i = 0; i < line.length; i++) {
    const ch = line[i] ?? "";
    if (ch === "'" && !inDouble) inSingle = !inSingle;
    else if (ch === '"' && !inSingle && line[i - 1] !== "\\") inDouble = !inDouble;
    else if (ch === "#" && !inSingle && !inDouble) {
      if (i === 0 || /\s/.test(line[i - 1] ?? "")) return line.slice(0, i);
    }
  }
  return line;
}

function joinLineContinuations(script: string): string[] {
  const rawLines = script.split(/\r?\n/);
  const joined: string[] = [];
  let buf = "";
  for (const raw of rawLines) {
    const trimmedEnd = raw.replace(/\s+$/, "");
    if (trimmedEnd.endsWith("\\")) {
      buf += `${trimmedEnd.slice(0, -1)} `;
    } else {
      joined.push(buf + raw);
      buf = "";
    }
  }
  if (buf) joined.push(buf);
  return joined;
}

export function sanitizeShellBlock(runScript: string): string[] {
  const active: string[] = [];
  let setPlusE = false;
  let pipefail = false;
  let heredocEnd: string | null = null;
  let inFunction = false;
  let braceDepth = 0;
  let ifDepth = 0;
  let loopDepth = 0;
  let caseDepth = 0;

  for (const raw of joinLineContinuations(runScript)) {
    const trimmedRaw = raw.trim();
    if (heredocEnd !== null) {
      if (trimmedRaw === heredocEnd) heredocEnd = null;
      continue;
    }
    const hdMatch = /<<-?\s*['"]?([A-Za-z0-9_]+)['"]?/.exec(raw);
    if (hdMatch?.[1]) {
      heredocEnd = hdMatch[1];
      continue;
    }

    const trimmed = stripShellComment(raw).trim();
    if (!trimmed) continue;

    if (inFunction) {
      braceDepth += (trimmed.match(/\{/g) ?? []).length - (trimmed.match(/\}/g) ?? []).length;
      if (braceDepth <= 0) {
        inFunction = false;
        braceDepth = 0;
      }
      continue;
    }
    if (/^(?:function\s+[A-Za-z_]\w*|[A-Za-z_]\w*\s*\(\s*\))\s*\{?/.test(trimmed)) {
      inFunction = true;
      braceDepth = (trimmed.match(/\{/g) ?? []).length - (trimmed.match(/\}/g) ?? []).length;
      if (braceDepth <= 0 && trimmed.includes("}")) inFunction = false;
      continue;
    }

    if (/^if\s+/.test(trimmed)) {
      if (!/\bfi\b/.test(trimmed)) ifDepth += 1;
      continue;
    }
    if (/^fi(?:\s|;|$)/.test(trimmed)) {
      ifDepth = Math.max(0, ifDepth - 1);
      continue;
    }
    if (/^(?:for|while|until)\s+/.test(trimmed)) {
      if (!/\bdone\b/.test(trimmed)) loopDepth += 1;
      continue;
    }
    if (/^done(?:\s|;|$)/.test(trimmed)) {
      loopDepth = Math.max(0, loopDepth - 1);
      continue;
    }
    if (/^case\s+/.test(trimmed)) {
      if (!/\besac\b/.test(trimmed)) caseDepth += 1;
      continue;
    }
    if (/^esac(?:\s|;|$)/.test(trimmed)) {
      caseDepth = Math.max(0, caseDepth - 1);
      continue;
    }
    if (ifDepth > 0 || loopDepth > 0 || caseDepth > 0) continue;

    if (/^set\s+(?:\+e|\+o\s+errexit)\b/.test(trimmed)) {
      setPlusE = true;
      continue;
    }
    if (/^set\s+(?:-e|-o\s+errexit)\b/.test(trimmed)) {
      setPlusE = false;
      if (/pipefail/.test(trimmed)) pipefail = true;
      continue;
    }
    if (/^set\s+-o\s+pipefail\b/.test(trimmed)) {
      pipefail = true;
      continue;
    }
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
      if (ch === quote && (quote === "'" || command[i - 1] !== "\\")) {
        quote = null;
      } else if (quote === '"' && (ch === "$" || ch === "`")) {
        return { parts: [], error: "Command contains forbidden shell substitution inside quotes." };
      } else {
        cur += ch;
      }
      continue;
    }
    if (ch === "'" || ch === '"') {
      quote = ch;
      hasToken = true;
      continue;
    }
    if (ch === "&" && next === "&") {
      if (hasToken || cur) {
        curTokens.push(cur);
        cur = "";
        hasToken = false;
      }
      if (curTokens.length === 0) return { parts: [], error: "Empty segment around &&." };
      parts.push(curTokens);
      curTokens = [];
      i += 1;
      continue;
    }
    if (ch === "&" || SHELL_META_UNQUOTED.test(ch)) {
      return { parts: [], error: `Command contains forbidden shell metacharacter '${ch}'.` };
    }
    if (/\s/.test(ch)) {
      if (hasToken || cur) {
        curTokens.push(cur);
        cur = "";
        hasToken = false;
      }
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

function readPackageScripts(repoRoot?: string): Record<string, string> {
  if (!repoRoot) return {};
  const pkgPath = path.join(repoRoot, "package.json");
  if (!fs.existsSync(pkgPath)) return {};
  try {
    const parsed = JSON.parse(fs.readFileSync(pkgPath, "utf8")) as { scripts?: Record<string, string> };
    return parsed.scripts && typeof parsed.scripts === "object" ? parsed.scripts : {};
  } catch {
    return {};
  }
}

function extractToolHead(tokens: readonly string[]): { head: string; toolArgs: string[]; error?: string } {
  const t0 = tokens[0] ?? "";
  if (!t0) return { head: "", toolArgs: [], error: "empty command" };
  if (FORBIDDEN_ENV_PREFIX.test(t0) || /^[A-Za-z_]\w*=/.test(t0)) {
    return { head: "", toolArgs: [], error: `env-variable override '${t0}' is forbidden` };
  }
  if (t0.includes("/") || t0.includes("\\")) {
    return { head: "", toolArgs: [], error: `path-qualified executable '${t0}' is forbidden` };
  }
  const low0 = t0.toLowerCase();
  if (FORBIDDEN_VERBS.has(low0)) {
    return { head: "", toolArgs: [], error: `forbidden no-op executable '${t0}'` };
  }

  let i = 0;
  if (low0 === "npx" || low0 === "bunx") {
    i = 1;
    while (i < tokens.length && (tokens[i] ?? "").startsWith("-")) i += 1;
    const bin = (tokens[i] ?? "").toLowerCase();
    return { head: bin, toolArgs: tokens.slice(i + 1) };
  }
  if ((low0 === "pnpm" || low0 === "yarn") && (tokens[1] ?? "").toLowerCase() === "exec") {
    const bin = (tokens[2] ?? "").toLowerCase();
    return { head: bin, toolArgs: tokens.slice(3) };
  }
  if ((low0 === "uv" || low0 === "poetry" || low0 === "pipenv") && (tokens[1] ?? "").toLowerCase() === "run") {
    i = 2;
    while (i < tokens.length && (tokens[i] ?? "").startsWith("-")) {
      const f = tokens[i] ?? "";
      i += f === "--project" || f === "--directory" || f === "--with" ? 2 : 1;
    }
    const bin = (tokens[i] ?? "").toLowerCase();
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

function hasForbiddenFlag(tokens: readonly string[]): string | null {
  const bin = (tokens[0] ?? "").toLowerCase();
  const isScriptInterp = bin === "node" || bin === "bun" || bin === "python" || bin === "python3" || bin === "ruby" || bin === "perl";
  for (const tok of tokens) {
    if (FORBIDDEN_FLAGS_EXACT.has(tok)) return `forbidden flag '${tok}'`;
    if (isScriptInterp && (tok === "-e" || tok === "-p" || tok === "-c")) return `forbidden inline-eval flag '${tok}'`;
    if (/^--(?:version|help|list-tests|no-run|passWithNoTests|showConfig|noCheck|preload)=?/i.test(tok)) {
      return `forbidden flag '${tok}'`;
    }
    if (/^-run=\^\$$/.test(tok)) return `empty Go test filter '${tok}'`;
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

  const scripts = readPackageScripts(repoRoot);
  const expand = (cmd: string, seen: Set<string>): { steps: string[][]; error?: string } => {
    const split = splitAndChainStrict(cmd.trim());
    if (split.error) return { steps: [], error: split.error };
    if (split.parts.length === 0) return { steps: [], error: "empty command" };

    const out: string[][] = [];
    for (const seg of split.parts) {
      const low0 = (seg[0] ?? "").toLowerCase();
      const low1 = (seg[1] ?? "").toLowerCase();
      let scriptName: string | undefined;
      if ((low0 === "bun" || low0 === "npm" || low0 === "pnpm" || low0 === "yarn") && low1 === "run" && seg[2]) {
        scriptName = seg[2];
      } else if ((low0 === "npm" || low0 === "pnpm" || low0 === "yarn") && low1 === "test") {
        scriptName = "test";
      } else if ((low0 === "pnpm" || low0 === "yarn") && seg[1] && scripts[seg[1]]) {
        scriptName = seg[1];
      }

      if (scriptName) {
        const body = scripts[scriptName];
        if (!body) return { steps: [], error: `unknown package.json script '${scriptName}'` };
        if (seen.has(scriptName)) continue;
        seen.add(scriptName);
        for (const hook of [`pre${scriptName}`, `post${scriptName}`]) {
          const hookBody = scripts[hook];
          if (hookBody) {
            const hRes = expand(hookBody, seen);
            if (hRes.error) return { steps: [], error: `lifecycle hook '${hook}': ${hRes.error}` };
          }
        }
        const sub = expand(body, seen);
        if (sub.error) return sub;
        out.push(...sub.steps);
      } else {
        out.push(seg);
      }
    }
    return { steps: out };
  };

  const expanded = expand(command, new Set());
  if (expanded.error) return { steps: [], error: `Rung ${rung}: ${expanded.error}` };

  const allowed = ALLOWED_TOOL_PREFIXES[rung];
  let hasR1Typecheck = false;

  for (const seg of expanded.steps) {
    const flagErr = hasForbiddenFlag(seg);
    if (flagErr) return { steps: [], error: `Rung ${rung}: ${flagErr}` };
    const { head, toolArgs, error } = extractToolHead(seg);
    if (error) return { steps: [], error: `Rung ${rung}: ${error}` };
    if (!allowed.some((re) => re.test(head))) {
      return { steps: [], error: `Rung ${rung}: executable '${head}' is not an allowed ${rung} verification tool.` };
    }
    if (head === "node bin/vstack.mjs" || head === "bun src/cli.ts") {
      const sub = (toolArgs[0] ?? "").toLowerCase();
      if (!ALLOWED_VSTACK_SUBCMDS.has(sub)) {
        return { steps: [], error: `Rung ${rung}: disallowed vstack subcommand '${sub}'.` };
      }
    }
    if (head === "pytest" && rung === "R6" && !toolArgs.some((a) => a.startsWith("--benchmark"))) {
      return { steps: [], error: "Rung R6: pytest must run with --benchmark / --benchmark-only." };
    }
    if (head === "bun scripts/check-perf-budget.mjs" || head === "node scripts/check-perf-budget.mjs") {
      if (repoRoot) {
        const absScript = path.join(repoRoot, "scripts/check-perf-budget.mjs");
        if (fs.existsSync(absScript)) {
          const body = fs.readFileSync(absScript, "utf8");
          if (!/\b(?:performance\.now|hrtime|fitEmpiricalBigO)\b/.test(body)) {
            return { steps: [], error: `Rung ${rung}: scripts/check-perf-budget.mjs lacks real timing measurement.` };
          }
        }
      }
    }
    if (rung === "R1" && /^(?:tsc|tsgo|mypy|pyright|basedpyright|cargo\s+(?:check|clippy)|dotnet\s+build|go\s+(?:vet|build))$/.test(head)) {
      hasR1Typecheck = true;
    }
  }

  if (rung === "R1" && !hasR1Typecheck) {
    return {
      steps: [],
      error: `Rung R1 command '${command}' must run a real typechecker/compiler (tsc, tsgo, mypy, pyright, cargo check/clippy, dotnet build, or go vet).`,
    };
  }
  return { steps: expanded.steps };
}

export function runArgvChain(
  steps: readonly string[][],
  cwd: string,
  env: NodeJS.ProcessEnv,
  timeoutMs: number,
): { status: number; stdout: string; stderr: string; signal: NodeJS.Signals | null; error?: Error } {
  let stdout = "";
  let stderr = "";
  for (const argv of steps) {
    const bin = argv[0] ?? "";
    if (!bin) return { status: 1, stdout, stderr: `${stderr}\nempty argv`, signal: null };
    const res = spawnSync(bin, argv.slice(1), {
      cwd,
      shell: false,
      env,
      encoding: "utf8",
      timeout: timeoutMs,
      maxBuffer: 16 * 1024 * 1024,
    });
    stdout += res.stdout ?? "";
    stderr += res.stderr ?? "";
    if (res.error || res.signal || res.status !== 0) {
      return {
        status: res.status ?? 1,
        stdout,
        stderr,
        signal: res.signal ?? null,
        error: res.error,
      };
    }
  }
  return { status: 0, stdout, stderr, signal: null };
}

export function validateExecutableCommand(
  rung: RungId | "canary",
  command: string,
  repoRoot?: string,
): string | null {
  return parseAndValidateCommandArgv(rung, command, repoRoot).error ?? null;
}
