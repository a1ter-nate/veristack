import { spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { sanitizeShellBlock } from "../rungs/command-audit.ts";
import type { Finding, RungId, RungManifest } from "../types.ts";

export interface DiffLineEvent {
  file: string;
  line: number;
  kind: "add" | "del";
  raw: string;
  code: string;
}

const STRICT_CONFIG_PATH = /(?:^|\/)(?:tsconfig(?:\.[^/]+)?\.json|\.?oxlintrc\.jsonc?|oxlint\.config\.ts|biome\.jsonc?|\.?ruff\.toml|pyproject\.toml|mypy\.ini|pyrightconfig\.json|\.?clippy\.toml|\.?golangci\.ya?ml|Directory\.Build\.props|Cargo\.toml|go\.mod|\.vstackignore|\.eslintignore|(?:vitest|vite|jest)\.config\.[cm]?[jt]s|jest\.config\.json|CODEOWNERS|(?:\.verification\/)?\.?vstack\.json|\.verification\/(?:invariants|rungs|behavior-changes|control-plan|escapes)\.json)$/i;
const TEST_FILE_PATH = /(?:\.(?:test|spec)\.[cm]?[jt]sx?$|_test\.go$|_tests?\.rs$|(?:^|\/)test_[^/]+\.py$|tests?\.cs$)/i;
const ASSERT_CALL = /\b(?:assert|expect|Assert\.|assert_eq!|assert_ne!|assert!|require\.|should\.)/;
const STRICT_ASSERT = /\.(?:toEqual|toStrictEqual|toBe|toMatchObject|toContainEqual)\s*\(|\bassert\.(?:equal|strictEqual|deepEqual|deepStrictEqual)\s*\(|\bassert_eq!\s*\(/;
const WEAK_ASSERT = /\.(?:toBeDefined|toBeTruthy|toBeFalsy)\s*\(\s*\)|\bAssert\.(?:NotNull|IsNotNull)\s*\(/;
const GATE_TOOL_LINE = /\b(?:vstack|fail-on-cheats|fail-on-errors|clippy|mypy|pyright|tsgo|oxlint|ruff|TreatWarningsAsErrors|red-before-fix)\b/;

function pushDiff(findings: Finding[], file: string, line: number, rule: string, message: string, fix: string): void {
  findings.push({ id: `DIFF:${rule}:${file}:${line}`, rule, category: "cheat", rung: "R0", severity: "error", file, line: Math.max(1, line), message, fix });
}

function hasBunfigCheat(raw: string): boolean {
  let section = "";
  for (const line of raw.split(/\r?\n/)) {
    const cleaned = line.replace(/#.*$/, "").trim();
    if (!cleaned) continue;
    const sec = /^\[([^\]]+)\]$/.exec(cleaned);
    if (sec?.[1]) { section = sec[1].trim().replace(/^["']|["']$/g, "").toLowerCase(); continue; }
    const kv = /^["']?([A-Za-z0-9_.-]+)["']?\s*=/.exec(cleaned);
    if (!kv?.[1]) continue;
    const key = kv[1].toLowerCase();
    if (key === "preload" || key.endsWith(".preload") || (section === "test" && key === "root") || key === "test.root") return true;
  }
  return false;
}

export function normalizeDiffMigrationPairs(
  events: readonly DiffLineEvent[],
): { events: DiffLineEvent[]; migratedJsToTsFiles: Set<string> } {
  const delOnlyJs = new Map<string, string>();
  const addOnlyTs = new Map<string, string>();
  const fileKinds = new Map<string, Set<"add" | "del">>();
  for (const ev of events) {
    const s = fileKinds.get(ev.file) ?? new Set<"add" | "del">();
    s.add(ev.kind);
    fileKinds.set(ev.file, s);
  }
  for (const [file, kinds] of fileKinds.entries()) {
    const jsMatch = /^(.+)\.([cm]?)js(x?)$/i.exec(file);
    if (jsMatch && kinds.has("del") && !kinds.has("add")) delOnlyJs.set(`${jsMatch[1]}.${jsMatch[2]}ts${jsMatch[3]}`, file);
    const tsMatch = /^(.+)\.([cm]?)ts(x?)$/i.exec(file);
    if (tsMatch && kinds.has("add") && !kinds.has("del")) addOnlyTs.set(file, file);
  }
  const remap = new Map<string, string>();
  const migratedJsToTsFiles = new Set<string>();
  for (const [tsPath, jsPath] of delOnlyJs.entries()) {
    if (addOnlyTs.has(tsPath)) { remap.set(jsPath, tsPath); migratedJsToTsFiles.add(tsPath); }
  }
  if (remap.size === 0) return { events: [...events], migratedJsToTsFiles };
  return {
    events: events.map((ev) => { const t = remap.get(ev.file); return t ? { ...ev, file: t, line: Math.max(1, ev.line) } : ev; }),
    migratedJsToTsFiles,
  };
}

export function scanUntrackedConfigCheats(repoPath: string): Finding[] {
  const res = spawnSync("git", ["-C", repoPath, "ls-files", "--others", "--exclude-standard"], { encoding: "utf8" });
  if (res.status !== 0) return [];
  const findings: Finding[] = [];
  for (const rel of (res.stdout ?? "").split(/\r?\n/).map((s) => s.trim()).filter(Boolean)) {
    const lower = rel.toLowerCase();
    const abs = path.join(repoPath, rel);
    if (!fs.existsSync(abs) || !fs.statSync(abs).isFile()) continue;
    const raw = fs.readFileSync(abs, "utf8");
    if (lower === ".vstackignore") {
      const nonEmpty = raw.split(/\r?\n/).map((l) => l.trim()).filter((l) => l && !l.startsWith("#"));
      if (nonEmpty.length > 0) pushDiff(findings, rel, 1, "diff-config-strictness-downgrade", `Untracked .vstackignore excludes ${nonEmpty.length} path(s).`, "Remove untracked .vstackignore exclusions and fix findings directly.");
    } else if (lower === ".vstack.json" || lower === ".verification/vstack.json") {
      if (/(?:"off"|"info"|"disabledRules"|"ignore"\s*:\s*\[)/i.test(raw)) {
        pushDiff(findings, rel, 1, "diff-config-strictness-downgrade", `Untracked ${rel} disables, downgrades, or ignores Veristack rules.`, "Remove untracked Veristack suppression config and fix findings directly.");
      }
    } else if (lower === "bunfig.toml" && hasBunfigCheat(raw)) {
      pushDiff(findings, rel, 1, "diff-config-strictness-downgrade", "Untracked bunfig.toml adds preload hook or overrides [test].root.", "Remove preload hook / [test].root override from bunfig.toml.");
    }
  }
  return findings;
}

export function auditDiffAntiEvasion(
  events: readonly DiffLineEvent[],
  _options: { migratedJsToTsFiles?: ReadonlySet<string> } = {},
): Finding[] {
  const findings: Finding[] = [];
  const testAddedAsserts = new Map<string, number>();
  const testAddedWeakAsserts = new Map<string, number>();
  const testDeletedAsserts = new Map<string, { count: number; strictCount: number; firstLine: number }>();
  const delThresholds = new Map<string, Map<string, number>>();
  const addThresholds = new Map<string, Array<{ key: string; val: number; line: number }>>();
  const codeownersDelOwners = new Map<string, number>();
  const codeownersAddOwners = new Map<string, number>();

  for (const ev of events) {
    const lower = ev.file.toLowerCase();
    const isWorkflow = /(?:^|\/)\.github\/workflows\/.+\.ya?ml$/i.test(lower);

    if (ev.kind === "add") {
      if (/\.[cm]?[jt]sx?$/.test(lower)) {
        if (/\/\/\s*@ts-(?:ignore|nocheck)\b|\/\*\s*@ts-(?:ignore|nocheck)\b/.test(ev.raw)) {
          pushDiff(findings, ev.file, ev.line, "diff-ts-suppression-added", "Added @ts-ignore/@ts-nocheck type-safety escape hatch in diff.", "Fix the underlying type error instead of disabling the TypeScript compiler.");
        } else if (/\/\/\s*@ts-expect-error\s*$/.test(ev.raw)) {
          pushDiff(findings, ev.file, ev.line, "diff-ts-suppression-added", "Added bare @ts-expect-error without a concrete justification in diff.", "Fix the type mismatch or document the exact invariant after @ts-expect-error.");
        } else if (/(?:eslint|oxlint)-disable(?:-next-line|-line)?\s*(?:\*\/|$)|biome-ignore\s+[a-z0-9/]+\s*:?\s*(?:\*\/|$)/i.test(ev.raw)) {
          pushDiff(findings, ev.file, ev.line, "diff-ts-suppression-added", "Added blanket linter suppression without reason in diff.", "Fix the lint finding instead of suppressing the linter.");
        }
      }
      if (lower.endsWith(".go") && /\/\/\s*nolint(?:\s*$|\s*:[a-z0-9,-]+\s*$)/i.test(ev.raw)) {
        pushDiff(findings, ev.file, ev.line, "diff-go-nolint-added", "Added unjustified //nolint directive in Go diff.", "Fix the linter issue or scope //nolint:<linter> with a concrete // justification.");
      }
      if (isWorkflow) {
        if (/^\s*if:\s*(?:false|\$\{\{\s*false\s*\}\})\s*$/i.test(ev.raw)) {
          pushDiff(findings, ev.file, ev.line, "diff-ci-safety-gate-removed", "Disabled CI job/step with 'if: false' in diff.", "Remove 'if: false' so CI gates execute unconditionally.");
        }
        if (/^\s*(?:-\s*)?run:\s*(?:echo\b|true\b|:\s*$)/i.test(ev.raw) && events.some((o) => o.kind === "del" && o.file === ev.file && /\b(?:test|pytest|vitest|jest|cargo|go\s+test|dotnet\s+test|bun\s+test|vstack)\b/i.test(o.raw))) {
          pushDiff(findings, ev.file, ev.line, "diff-ci-safety-gate-removed", "Replaced CI test/verification step with a no-op echo/true command in diff.", "Restore the real test/verification step.");
        }
      }
      if (lower.endsWith("package.json")) {
        if (/"(?:test|check|lint|typecheck|verify)[^"]*"\s*:\s*"\s*(?:true|:|echo\b|exit\s+0)/i.test(ev.raw)) {
          pushDiff(findings, ev.file, ev.line, "diff-config-strictness-downgrade", "Replaced package.json verification script with a no-op command in diff.", "Keep real test/lint/typecheck commands in package.json scripts.");
        }
      }
      if (STRICT_CONFIG_PATH.test(ev.file)) {
        if (/"(?:strict|strictNullChecks|noImplicitAny|exactOptionalPropertyTypes)"\s*:\s*false/.test(ev.raw)) {
          pushDiff(findings, ev.file, ev.line, "diff-config-strictness-downgrade", "Downgraded TypeScript strictness flag to false in config diff.", "Keep TypeScript strict compiler flags enabled.");
        }
        if (lower.endsWith(".vstackignore") && ev.raw.trim().length > 0 && !ev.raw.trim().startsWith("#")) {
          pushDiff(findings, ev.file, ev.line, "diff-config-strictness-downgrade", `Added new path exclusion ('${ev.raw.trim()}') to .vstackignore in diff.`, "Fix findings directly instead of excluding paths from verification.");
        }
        if (/(?:oxlint|biome|ruff|mypy|clippy|golangci|pyproject\.toml|vstack\.json)/i.test(lower) && /(?:"off"|\bdisallow_untyped_defs\s*=\s*false|\bstrict\s*=\s*false|\bignore\s*=\s*\[|"disabledRules"\s*:|"ignore"\s*:\s*\[)/i.test(ev.raw)) {
          pushDiff(findings, ev.file, ev.line, "diff-config-strictness-downgrade", "Relaxed linter/typechecker strictness rule in config diff.", "Keep strict lint/type rules enforced rather than disabling them in config.");
        }
        if (/vstack\.json$/i.test(lower) && /:\s*"info"/i.test(ev.raw)) {
          pushDiff(findings, ev.file, ev.line, "diff-config-strictness-downgrade", "Downgraded Veristack rule/category severity to 'info' in vstack.json diff.", "Keep rule severities intact instead of silencing them to 'info'.");
        }
        if (/(?:pyproject\.toml|vitest\.config|vite\.config|jest\.config)/i.test(lower)) {
          for (const tm of ev.raw.matchAll(/\b(fail_under|lines|branches|functions|statements|thresholds)\s*[:=]\s*(\d+(?:\.\d+)?)/gi)) {
            const arr = addThresholds.get(ev.file) ?? [];
            arr.push({ key: (tm[1] ?? "").toLowerCase(), val: Number(tm[2]), line: ev.line });
            addThresholds.set(ev.file, arr);
          }
        }
        if (lower.endsWith("codeowners") && /@[A-Za-z0-9_.-]+/.test(ev.raw) && !ev.raw.trim().startsWith("#")) {
          codeownersAddOwners.set(ev.file, (codeownersAddOwners.get(ev.file) ?? 0) + 1);
        }
      }
      if (TEST_FILE_PATH.test(ev.file) && ASSERT_CALL.test(ev.code)) {
        testAddedAsserts.set(ev.file, (testAddedAsserts.get(ev.file) ?? 0) + 1);
        if (WEAK_ASSERT.test(ev.code)) testAddedWeakAsserts.set(ev.file, (testAddedWeakAsserts.get(ev.file) ?? 0) + 1);
      }
    } else {
      if (/tsconfig(?:\.[^/]+)?\.json$/i.test(lower) && /"(?:strict|strictNullChecks|noImplicitAny|exactOptionalPropertyTypes)"\s*:\s*true/.test(ev.raw)) {
        const readded = events.some((o) => o.kind === "add" && o.file === ev.file && /"(?:strict|strictNullChecks|noImplicitAny|exactOptionalPropertyTypes)"\s*:\s*true/.test(o.raw));
        if (!readded) pushDiff(findings, ev.file, ev.line, "diff-config-strictness-downgrade", "Removed TypeScript strictness flag from tsconfig in diff.", "Keep TypeScript strict compiler flags enabled.");
      }
      if (/(?:pyproject\.toml|vitest\.config|vite\.config|jest\.config)/i.test(lower)) {
        for (const tm of ev.raw.matchAll(/\b(fail_under|lines|branches|functions|statements|thresholds)\s*[:=]\s*(\d+(?:\.\d+)?)/gi)) {
          const map = delThresholds.get(ev.file) ?? new Map<string, number>();
          const k = (tm[1] ?? "").toLowerCase();
          map.set(k, Math.max(map.get(k) ?? 0, Number(tm[2])));
          delThresholds.set(ev.file, map);
        }
      }
      if (lower.endsWith("codeowners") && /@[A-Za-z0-9_.-]+/.test(ev.raw) && !ev.raw.trim().startsWith("#")) {
        codeownersDelOwners.set(ev.file, (codeownersDelOwners.get(ev.file) ?? 0) + 1);
      }
      if (isWorkflow && /^\s*(?:pull_request|push)\s*:/i.test(ev.raw)) {
        const keptPrTrigger = events.some((o) => o.kind === "add" && o.file === ev.file && /^\s*(?:pull_request|push|merge_group)\s*:/i.test(o.raw));
        const switchedManual = events.some((o) => o.kind === "add" && o.file === ev.file && /^\s*workflow_dispatch\s*:/i.test(o.raw));
        if (switchedManual && !keptPrTrigger) {
          pushDiff(findings, ev.file, ev.line, "diff-ci-safety-gate-removed", "Changed PR-blocking workflow trigger to manual workflow_dispatch in diff.", "Keep pull_request/push triggers active on CI workflows.");
        }
      }
      if (TEST_FILE_PATH.test(ev.file) && ASSERT_CALL.test(ev.code)) {
        const cur = testDeletedAsserts.get(ev.file) ?? { count: 0, strictCount: 0, firstLine: ev.line };
        cur.count += 1;
        if (STRICT_ASSERT.test(ev.code)) cur.strictCount += 1;
        testDeletedAsserts.set(ev.file, cur);
      }
      const isCiOrHook = /(?:^|\/)(?:\.github\/workflows\/|lefthook\.yml|\.husky\/|package\.json)/i.test(ev.file);
      if (/\.verification\/invariants\.json$/i.test(ev.file) && /"kind"\s*:/.test(ev.raw)) {
        pushDiff(findings, ev.file, ev.line, "diff-config-strictness-downgrade", "Deleted dynamic invariant entry from .verification/invariants.json in diff.", "Keep locked dynamic invariants intact.");
      }
      if (isCiOrHook && GATE_TOOL_LINE.test(ev.raw) && !ev.raw.trim().startsWith("#")) {
        const hasMatchingAdd = events.some((other) => {
          if (other.kind !== "add" || other.file !== ev.file || !GATE_TOOL_LINE.test(other.raw)) return false;
          const cmdText = other.raw.replace(/^\s*(?:-\s*)?run:\s*/, "").trim();
          return sanitizeShellBlock(cmdText).length > 0;
        });
        if (!hasMatchingAdd) {
          pushDiff(findings, ev.file, ev.line, "diff-ci-safety-gate-removed", "Removed verification/linter gate from CI workflow or hook without an executable replacement.", "Keep verification gates active in CI and hooks.");
        }
      }
    }
  }

  for (const [file, addedList] of addThresholds.entries()) {
    const delMap = delThresholds.get(file);
    if (!delMap) continue;
    for (const a of addedList) {
      const prev = delMap.get(a.key);
      if (prev !== undefined && a.val < prev) {
        pushDiff(findings, file, a.line, "diff-config-strictness-downgrade", `Lowered coverage/quality threshold '${a.key}' from ${prev} to ${a.val} in ${file}.`, "Keep coverage and quality thresholds at or above the base branch floor.");
      }
    }
  }
  for (const [file, delCount] of codeownersDelOwners.entries()) {
    const addCount = codeownersAddOwners.get(file) ?? 0;
    if (delCount > addCount) {
      pushDiff(findings, file, 1, "diff-config-strictness-downgrade", `Removed ${delCount - addCount} CODEOWNERS protection rule(s) in ${file}.`, "Keep CODEOWNERS control-plane ownership intact.");
    }
  }
  for (const [file, delInfo] of testDeletedAsserts.entries()) {
    const addedCount = testAddedAsserts.get(file) ?? 0;
    const weakAdded = testAddedWeakAsserts.get(file) ?? 0;
    if ((delInfo.count >= 2 && addedCount < delInfo.count) || (delInfo.strictCount >= 1 && addedCount < delInfo.count) || (delInfo.strictCount > 0 && weakAdded > 0 && addedCount <= delInfo.strictCount)) {
      pushDiff(
        findings, file, delInfo.firstLine, "diff-assertion-deleted",
        weakAdded > 0 && delInfo.strictCount > 0 ? `Weakened ${delInfo.strictCount} strict assertion(s) into existence-only assertion(s) in ${file}.` : `Net loss of test assertions in ${file} (deleted ${delInfo.count}, added ${addedCount}).`,
        "Preserve or strengthen exact behavioral assertions; never delete or dilute assertions to make a failing test pass.",
      );
    }
  }
  return findings;
}

function collectReferencedScriptsAndFiles(commands: readonly string[], pkgScripts: Record<string, string>): { scripts: Set<string>; localScripts: Set<string> } {
  const scripts = new Set<string>();
  const localScripts = new Set<string>();
  const queue = [...commands];
  for (let qi = 0; qi < queue.length; qi++) {
    const cmd = queue[qi] ?? "";
    for (const m of cmd.matchAll(/\b(?:bun|npm|pnpm|yarn)\s+(?:run\s+)?([A-Za-z0-9:_-]+)/g)) {
      const name = m[1] ?? "";
      if (name && pkgScripts[name] && !scripts.has(name)) {
        scripts.add(name);
        queue.push(pkgScripts[name] ?? "");
        for (const hook of [`pre${name}`, `post${name}`]) {
          if (pkgScripts[hook] && !scripts.has(hook)) { scripts.add(hook); queue.push(pkgScripts[hook] ?? ""); }
        }
      }
    }
    for (const m of cmd.matchAll(/\b(?:node|bun)\s+(scripts\/[^\s"']+\.[cm]?[jt]s)/g)) {
      if (m[1]) localScripts.add(m[1]);
    }
  }
  return { scripts, localScripts };
}

export function auditManifestDowngrade(
  repoRoot: string,
  baseRef: string,
  options: { failClosedOnMissingBase?: boolean } = {},
): Finding[] {
  const makeErr = (id: string, file: string, msg: string): Finding => ({
    id: `DIFF:manifest:${id}`, rule: "diff-manifest-downgrade", category: "cheat", rung: "R0", severity: "error", file, line: 1, message: msg,
    fix: "Keep or strengthen verification control-plane files; set VSTACK_ALLOW_MANIFEST_CHANGE=1 only for reviewed human upgrades.",
  });
  const revCheck = spawnSync("git", ["-C", repoRoot, "rev-parse", "--verify", `${baseRef}^{commit}`], { encoding: "utf8" });
  if (revCheck.status !== 0) {
    return options.failClosedOnMissingBase ? [makeErr("missing-base", ".git", `Base ref '${baseRef}' could not be resolved for control-plane lock — failing closed.`)] : [];
  }
  const baseShow = spawnSync("git", ["-C", repoRoot, "show", `${baseRef}:.verification/rungs.json`], { encoding: "utf8" });
  if (baseShow.status !== 0) {
    return options.failClosedOnMissingBase && fs.existsSync(path.join(repoRoot, ".verification/rungs.json"))
      ? [makeErr("missing-base-manifest", ".verification/rungs.json", `Could not read .verification/rungs.json at base ref '${baseRef}'.`)]
      : [];
  }
  const headPath = path.join(repoRoot, ".verification/rungs.json");
  if (!fs.existsSync(headPath)) {
    return [makeErr("deleted", ".verification/rungs.json", "Deleted .verification/rungs.json verification manifest compared to base branch.")];
  }
  try {
    const base = JSON.parse(baseShow.stdout) as Partial<RungManifest>;
    const head = JSON.parse(fs.readFileSync(headPath, "utf8")) as Partial<RungManifest>;
    const findings: Finding[] = [];
    if (base.archetype && head.archetype && head.archetype !== base.archetype && head.archetype !== "fullstack") {
      findings.push(makeErr("archetype", ".verification/rungs.json", `Changed manifest archetype '${base.archetype}' -> '${head.archetype}' vs ${baseRef}.`));
    }
    const baseAllow = new Set(base.allowExcluded ?? []);
    for (const pat of head.allowExcluded ?? []) {
      if (!baseAllow.has(pat)) findings.push(makeErr(`allow-${pat}`, ".verification/rungs.json", `Widened allowExcluded with '${pat}' vs ${baseRef}.`));
    }
    const baseCmds: string[] = [];
    for (const [rung, baseEntry] of Object.entries(base.rungs ?? {})) {
      if (!baseEntry) continue;
      baseCmds.push(baseEntry.command);
      if (baseEntry.canary?.testCommand) baseCmds.push(baseEntry.canary.testCommand);
      const headEntry = head.rungs?.[rung as RungId];
      if (!headEntry) { findings.push(makeErr(`drop-${rung}`, ".verification/rungs.json", `Removed rung ${rung} from .verification/rungs.json vs ${baseRef}.`)); continue; }
      if (baseEntry.required !== false && headEntry.required === false) findings.push(makeErr(`req-${rung}`, ".verification/rungs.json", `Downgraded rung ${rung} required=true -> false vs ${baseRef}.`));
      if (headEntry.command !== baseEntry.command) findings.push(makeErr(`cmd-${rung}`, ".verification/rungs.json", `Modified rung ${rung} verification command vs ${baseRef}.`));
      if (baseEntry.canary?.enabled && !headEntry.canary?.enabled) findings.push(makeErr(`canary-off-${rung}`, ".verification/rungs.json", `Disabled planted-fault canary on rung ${rung} vs ${baseRef}.`));
      if (baseEntry.canary?.enabled && headEntry.canary?.enabled) {
        if ((headEntry.canary.minKillRate ?? 0.8) < (baseEntry.canary.minKillRate ?? 0.8)) findings.push(makeErr(`canary-rate-${rung}`, ".verification/rungs.json", `Lowered canary minKillRate on ${rung} vs ${baseRef}.`));
        if ((headEntry.canary.maxMutants ?? 6) < (baseEntry.canary.maxMutants ?? 6)) findings.push(makeErr(`canary-mut-${rung}`, ".verification/rungs.json", `Lowered canary maxMutants on ${rung} vs ${baseRef}.`));
        if ((headEntry.canary.testCommand ?? "") !== (baseEntry.canary.testCommand ?? "")) findings.push(makeErr(`canary-cmd-${rung}`, ".verification/rungs.json", `Modified canary.testCommand on ${rung} vs ${baseRef}.`));
        const headTargets = new Set(headEntry.canary.targets ?? []);
        for (const t of baseEntry.canary.targets ?? []) {
          if (!headTargets.has(t)) findings.push(makeErr(`canary-target-${rung}-${t}`, ".verification/rungs.json", `Removed canary target '${t}' on ${rung} vs ${baseRef}.`));
        }
      }
    }
    for (const ws of base.workspaces ?? []) {
      if (!(head.workspaces ?? []).some((h) => h.path === ws.path)) findings.push(makeErr(`ws-${ws.path}`, ".verification/rungs.json", `Removed workspace '${ws.path}' from .verification/rungs.json vs ${baseRef}.`));
    }

    const basePkgShow = spawnSync("git", ["-C", repoRoot, "show", `${baseRef}:package.json`], { encoding: "utf8" });
    const headPkgPath = path.join(repoRoot, "package.json");
    if (basePkgShow.status === 0 && fs.existsSync(headPkgPath)) {
      try {
        const basePkg = JSON.parse(basePkgShow.stdout) as { scripts?: Record<string, string> };
        const headPkg = JSON.parse(fs.readFileSync(headPkgPath, "utf8")) as { scripts?: Record<string, string> };
        const baseScripts = basePkg.scripts ?? {};
        const headScripts = headPkg.scripts ?? {};
        const refs = collectReferencedScriptsAndFiles(baseCmds, baseScripts);
        for (const sName of refs.scripts) {
          if (headScripts[sName] !== baseScripts[sName]) {
            findings.push(makeErr(`pkg-script-${sName}`, "package.json", `Modified rung-referenced package.json script '${sName}' vs ${baseRef}.`));
          }
        }
        for (const relScript of refs.localScripts) {
          const baseSc = spawnSync("git", ["-C", repoRoot, "show", `${baseRef}:${relScript}`], { encoding: "utf8" });
          const headScPath = path.join(repoRoot, relScript);
          if (baseSc.status === 0 && (!fs.existsSync(headScPath) || fs.readFileSync(headScPath, "utf8") !== baseSc.stdout)) {
            findings.push(makeErr(`gate-script-${relScript}`, relScript, `Modified or deleted rung-referenced gate script '${relScript}' vs ${baseRef}.`));
          }
        }
      } catch {
        findings.push(makeErr("pkg-json-invalid", "package.json", "Modified package.json is not valid JSON."));
      }
    }
    return findings;
  } catch {
    return [makeErr("invalid-json", ".verification/rungs.json", "Modified .verification/rungs.json is not valid JSON.")];
  }
}
