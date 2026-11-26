import { spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import type { Finding, RungId, RungManifest } from "../types.ts";

const FORBIDDEN_RAW_SYNTAX =
  /\|\||(?:^|[\s;&])!\s|\s&\s*$|(?:\b(?:node|bun|deno)\s+(?:-e|--eval|-p|--print)\b)|(?:\bpython3?\s+-c\b)|(?:\b(?:sh|bash|zsh)\s+-c\b)|\b(?:eval|exec|alias|sleep)\b|\bgit\s+(?:diff|status)\b|\b(?:sha256sum|md5sum|shasum|readFileSync|realpathSync)\b|\bset\s+(?:\+e|\+o\s+errexit)\b|(?:^|[\s;|&])exit(?:\s+0)?(?=$|[\s;|&])|(?:^|[\s;|&]):(?=$|[\s;|&])|\s(?:--version|-V|--help|-h|--list-tests|--list)\b/i;

const RUNNER_WRAPPERS = new Set(["npx", "bunx", "pnpm", "yarn", "npm", "uv", "poetry", "pipenv", "dotnet", "cargo", "go", "env"]);

const ALLOWED_TOOL_PREFIXES: Record<RungId | "canary", readonly RegExp[]> = {
  R0: [
    /^(?:oxlint|oxfmt|eslint|prettier|biome|ruff|golangci-lint|gofmt|vstack|dprint|stylua|rubocop|ktlint|checkstyle)$/,
    /^(?:cargo\s+(?:fmt|clippy)|dotnet\s+format|node\s+bin\/vstack\.mjs|bun\s+src\/cli\.ts)$/,
  ],
  R1: [
    /^(?:tsc|tsgo|mypy|pyright|basedpyright|knip|deslop-please|vulture|deadcode|import-linter|pyright)$/,
    /^(?:cargo\s+(?:check|clippy|udeps|machete)|dotnet\s+build|go\s+(?:vet|build)|node\s+scripts\/check-max-lines\.mjs|bun\s+scripts\/check-max-lines\.mjs)$/,
  ],
  R2: [
    /^(?:vitest|jest|mocha|ava|pytest|phpunit|rspec|xunit|nunit|ctest)$/,
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
    /^(?:stryker|mutmut|pitest|gremlins|go-mutesting|crosshair|bend|quint|dafny|kani|stateright|chromatic|percy|argos|bombadil|vstack)$/,
    /^(?:cargo\s+mutants|dotnet\s+stryker|node\s+bin\/vstack\.mjs|bun\s+src\/cli\.ts)$/,
  ],
  R6: [
    /^(?:k6|lighthouse|lhci|locust|mitata|tinybench|divan|nbomber|hyperfine|criterion|vstack)$/,
    /^(?:cargo\s+bench|pytest\s+--benchmark|go\s+test|dotnet\s+run|node\s+bin\/vstack\.mjs|bun\s+src\/cli\.ts|bun\s+scripts\/check-perf-budget\.mjs|node\s+scripts\/check-perf-budget\.mjs)$/,
  ],
  R7: [/^(?:playwright|cypress|maestro|detox|webdriverio|wdio)$/],
  R8: [/^(?:k6|playwright|curl|synthetic|canary|smoke-prod|healthcheck)$/],
  canary: [
    /^(?:vitest|jest|mocha|ava|pytest|phpunit|rspec)$/,
    /^(?:bun\s+test|node\s+--test|dotnet\s+test|cargo\s+(?:test|nextest)|go\s+test)$/,
  ],
};

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
      braceDepth += (trimmed.match(/\{/g) ?? []).length;
      braceDepth -= (trimmed.match(/\}/g) ?? []).length;
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

    if (/^(?:if\s+|elif\s+|else\b|then\b|fi\b|for\s+|while\s+|until\s+|case\s+|esac\b|alias\s+|\$\{\{|!(\s|$))/.test(trimmed)) {
      continue;
    }
    if (/^(?:echo|printf|true|sleep)(?:\s|;|$)/.test(trimmed)) continue;
    if (/^:(?:\s|;|$)/.test(trimmed)) continue;
    if (/^false(?:\s|&&|\|\||;|$)/.test(trimmed)) continue;
    if (/^\.\/vstack\b/.test(trimmed)) continue;
    if (/\|\|/.test(trimmed)) continue;
    if (/(?:^|[^&])&\s*$/.test(trimmed)) continue;
    if (/&&\s*(?:echo|printf|true|:)(?:\s|$)/.test(trimmed)) continue;
    if (!pipefail && /\|\s*(?:tee|cat|true|head|tail|grep|awk|sed)\b/.test(trimmed)) continue;
    if (/\s(?:--help|-h|--version|-V|--list-tests)(?:\s|$)/.test(trimmed)) continue;
    active.push(trimmed);
  }
  return active;
}

function tokenizeSimple(segment: string): string[] {
  const tokens: string[] = [];
  let cur = "";
  let quote: "'" | '"' | null = null;
  for (let i = 0; i < segment.length; i++) {
    const ch = segment[i] ?? "";
    if (quote) {
      if (ch === quote && segment[i - 1] !== "\\") quote = null;
      else cur += ch;
    } else if (ch === "'" || ch === '"') {
      quote = ch;
    } else if (/\s/.test(ch)) {
      if (cur) {
        tokens.push(cur);
        cur = "";
      }
    } else {
      cur += ch;
    }
  }
  if (cur) tokens.push(cur);
  return tokens;
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

function extractToolHead(tokens: readonly string[]): string {
  let idx = 0;
  while (idx < tokens.length && /^[A-Za-z_]\w*=/.test(tokens[idx] ?? "")) idx += 1;
  const t0 = (tokens[idx] ?? "").toLowerCase();
  const t1 = (tokens[idx + 1] ?? "").toLowerCase();
  const t2 = (tokens[idx + 2] ?? "").toLowerCase();
  if (!t0) return "";
  if (t0 === "npx" || t0 === "bunx") {
    return t1.startsWith("-") ? (tokens[idx + 2] ?? "").toLowerCase() : t1;
  }
  if ((t0 === "pnpm" || t0 === "yarn") && t1 === "exec") return t2;
  if (t0 === "uv" && t1 === "run") {
    let j = idx + 2;
    while (j < tokens.length && (tokens[j] ?? "").startsWith("-")) {
      j += (tokens[j] === "--project" || tokens[j] === "--directory") ? 2 : 1;
    }
    return (tokens[j] ?? "").toLowerCase();
  }
  if (t0 === "node" || t0 === "bun") {
    return t1 ? `${t0} ${t1}` : t0;
  }
  if (RUNNER_WRAPPERS.has(t0) && t1) return `${t0} ${t1}`;
  return t0;
}

function expandSegments(
  command: string,
  scripts: Record<string, string>,
  seenScripts: Set<string>,
): { segments: string[]; error?: string } {
  if (FORBIDDEN_RAW_SYNTAX.test(command)) {
    return { segments: [], error: `Command '${command}' contains forbidden no-op, inline-eval, version/help, or failure-swallowing syntax.` };
  }
  if (/(?:^|[^|])\|(?:[^|]|$)/.test(command)) {
    return { segments: [], error: `Command '${command}' uses a shell pipe, which can hide exit codes.` };
  }
  const activeLines = sanitizeShellBlock(command);
  if (activeLines.length === 0) {
    return { segments: [], error: `Command '${command}' is a no-op or swallows failures.` };
  }

  const out: string[] = [];
  for (const line of activeLines) {
    for (const part of line.split(/\s*(?:&&|;)\s*/)) {
      const seg = part.trim();
      if (!seg) continue;
      const tokens = tokenizeSimple(seg);
      let idx = 0;
      while (idx < tokens.length && /^[A-Za-z_]\w*=/.test(tokens[idx] ?? "")) idx += 1;
      const t0 = (tokens[idx] ?? "").toLowerCase();
      const t1 = (tokens[idx + 1] ?? "").toLowerCase();
      const t2 = tokens[idx + 2] ?? "";
      if (t0 === "cd") continue;

      let scriptName: string | undefined;
      if ((t0 === "bun" || t0 === "npm" || t0 === "pnpm" || t0 === "yarn") && t1 === "run" && t2) {
        scriptName = t2;
      } else if ((t0 === "npm" || t0 === "pnpm" || t0 === "yarn") && t1 === "test") {
        scriptName = "test";
      } else if ((t0 === "pnpm" || t0 === "yarn") && t1 && scripts[t1]) {
        scriptName = t1;
      }

      const scriptBody = scriptName ? scripts[scriptName] : undefined;
      if (scriptName && scriptBody) {
        if (seenScripts.has(scriptName)) continue;
        seenScripts.add(scriptName);
        const expanded = expandSegments(scriptBody, scripts, seenScripts);
        if (expanded.error) return expanded;
        out.push(...expanded.segments);
      } else {
        out.push(seg);
      }
    }
  }
  return { segments: out };
}

export function validateExecutableCommand(
  rung: RungId | "canary",
  command: string,
  repoRoot?: string,
): string | null {
  const scripts = readPackageScripts(repoRoot);
  const { segments, error } = expandSegments(command, scripts, new Set());
  if (error) return `Rung ${rung}: ${error}`;
  if (segments.length === 0) return `Rung ${rung} command '${command}' has no executable verification steps.`;

  const allowed = ALLOWED_TOOL_PREFIXES[rung];
  let matchedRealTool = false;

  for (const seg of segments) {
    const tokens = tokenizeSimple(seg);
    const head = extractToolHead(tokens);
    if (!head) continue;
    if (allowed.some((re) => re.test(head))) {
      if (head === "bun scripts/check-perf-budget.mjs" || head === "node scripts/check-perf-budget.mjs") {
        if (repoRoot) {
          const absScript = path.join(repoRoot, "scripts/check-perf-budget.mjs");
          if (fs.existsSync(absScript)) {
            const body = fs.readFileSync(absScript, "utf8");
            if (!/\b(?:performance\.now|hrtime|median|fitEmpiricalBigO|check-perf-budget)\b/.test(body)) {
              return `Rung ${rung}: scripts/check-perf-budget.mjs does not contain real timing/budget measurement.`;
            }
          }
        }
      }
      matchedRealTool = true;
    }
  }

  if (!matchedRealTool) {
    return `Rung ${rung} command '${command}' does not invoke a recognized ${rung} verification executable (wrapper scripts and keyword arguments are rejected).`;
  }

  if (rung === "R1") {
    const hasTypeOrBuild = segments.some((seg) => {
      const h = extractToolHead(tokenizeSimple(seg));
      return /^(?:tsc|tsgo|mypy|pyright|basedpyright|cargo\s+(?:check|clippy)|dotnet\s+build|go\s+(?:vet|build))$/.test(h);
    });
    if (!hasTypeOrBuild) {
      return `Rung R1 command '${command}' must run a real typechecker/compiler (tsc, tsgo, mypy, pyright, cargo check/clippy, dotnet build, or go vet).`;
    }
  }

  return null;
}

const ARCH_RANK: Record<string, number> = { library: 0, frontend: 1, service: 2, fullstack: 3 };

export function auditManifestDowngrade(repoRoot: string, baseRef: string): Finding[] {
  const baseShow = spawnSync("git", ["-C", repoRoot, "show", `${baseRef}:.verification/rungs.json`], {
    encoding: "utf8",
  });
  if (baseShow.status !== 0) return [];
  const headPath = path.join(repoRoot, ".verification/rungs.json");
  if (!fs.existsSync(headPath)) {
    return [{
      id: "DIFF:manifest-deleted:.verification/rungs.json",
      rule: "diff-manifest-downgrade",
      category: "cheat",
      rung: "R0",
      severity: "error",
      file: ".verification/rungs.json",
      line: 1,
      message: "Deleted .verification/rungs.json verification manifest compared to base branch.",
      fix: "Restore .verification/rungs.json; removing rung enforcement is forbidden.",
    }];
  }
  try {
    const base = JSON.parse(baseShow.stdout) as Partial<RungManifest>;
    const head = JSON.parse(fs.readFileSync(headPath, "utf8")) as Partial<RungManifest>;
    const findings: Finding[] = [];
    const pushErr = (id: string, msg: string): void => {
      findings.push({
        id: `DIFF:manifest:${id}`,
        rule: "diff-manifest-downgrade",
        category: "cheat",
        rung: "R0",
        severity: "error",
        file: ".verification/rungs.json",
        line: 1,
        message: msg,
        fix: "Keep or strengthen verification manifest requirements instead of weakening them in a PR.",
      });
    };
    if (base.archetype && head.archetype && (ARCH_RANK[head.archetype] ?? 0) < (ARCH_RANK[base.archetype] ?? 0)) {
      pushErr("archetype", `Downgraded manifest archetype '${base.archetype}' -> '${head.archetype}'.`);
    }
    const baseAllow = new Set(base.allowExcluded ?? []);
    for (const pat of head.allowExcluded ?? []) {
      if (!baseAllow.has(pat)) pushErr(`allow-${pat}`, `Widened allowExcluded with '${pat}' vs ${baseRef}.`);
    }
    for (const [rung, baseEntry] of Object.entries(base.rungs ?? {})) {
      if (!baseEntry) continue;
      const headEntry = head.rungs?.[rung as RungId];
      if (!headEntry) {
        pushErr(`drop-${rung}`, `Removed rung ${rung} from .verification/rungs.json vs ${baseRef}.`);
        continue;
      }
      if (baseEntry.canary?.enabled && !headEntry.canary?.enabled) {
        pushErr(`canary-off-${rung}`, `Disabled planted-fault canary on rung ${rung} vs ${baseRef}.`);
      }
      if (baseEntry.canary?.enabled && headEntry.canary?.enabled) {
        const bRate = baseEntry.canary.minKillRate ?? 0.8;
        const hRate = headEntry.canary.minKillRate ?? 0.8;
        if (hRate < bRate) pushErr(`canary-rate-${rung}`, `Lowered canary minKillRate on ${rung} (${bRate} -> ${hRate}).`);
        const bMut = baseEntry.canary.maxMutants ?? 6;
        const hMut = headEntry.canary.maxMutants ?? 6;
        if (hMut < bMut) pushErr(`canary-mut-${rung}`, `Lowered canary maxMutants on ${rung} (${bMut} -> ${hMut}).`);
      }
    }
    return findings;
  } catch {
    return [];
  }
}
