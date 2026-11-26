import fs from "node:fs";
import path from "node:path";
import { sanitizeShellBlock } from "../rungs/command-audit.ts";
import { auditBunfigContent, runGitClean, VERIFICATION_TOOLS } from "../rungs/config-audit.ts";
import type { Finding, RungId, RungManifest } from "../types.ts";

export interface DiffLineEvent {
  file: string;
  line: number;
  kind: "add" | "del";
  raw: string;
  code: string;
}

const STRICT_CONFIG_PATH = /(?:^|\/)(?:\.gitattributes|tsconfig(?:\.[^/]+)?\.json|\.?oxlintrc\.jsonc?|oxlint\.config\.ts|biome\.jsonc?|\.?ruff\.toml|pyproject\.toml|mypy\.ini|pyrightconfig\.json|\.?clippy\.toml|\.?golangci\.ya?ml|Directory\.Build\.props|Cargo\.toml|go\.mod|\.vstackignore|\.eslintignore|(?:vitest|vite|jest)\.config\.[cm]?[jt]s|jest\.config\.json|CODEOWNERS|(?:\.verification\/)?\.?vstack\.json|\.verification\/(?:invariants|rungs|behavior-changes|control-plan|escapes)\.json)$/i;
const TEST_FILE_PATH = /(?:\.(?:test|spec)\.[cm]?[jt]sx?$|_test\.go$|_tests?\.rs$|(?:^|\/)test_[^/]+\.py$|tests?\.cs$)/i;
const ASSERT_CALL = /\b(?:assert|expect|Assert\.|assert_eq!|assert_ne!|assert!|require\.|should\.)/;
const STRICT_ASSERT = /\.(?:toEqual|toStrictEqual|toBe|toMatchObject|toContainEqual)\s*\(|\bassert\.(?:equal|strictEqual|deepEqual|deepStrictEqual)\s*\(|\bassert_eq!\s*\(/;
const WEAK_ASSERT = /\.(?:toBeDefined|toBeTruthy|toBeFalsy)\s*\(\s*\)|\bAssert\.(?:NotNull|IsNotNull)\s*\(/;
const GATE_TOOL_LINE = /\b(?:vstack|fail-on-cheats|fail-on-errors|clippy|mypy|pyright|tsgo|oxlint|ruff|TreatWarningsAsErrors|red-before-fix)\b/;

function pushDiff(findings: Finding[], file: string, line: number, rule: string, message: string, fix: string): void {
  findings.push({ id: `DIFF:${rule}:${file}:${line}`, rule, category: "cheat", rung: "R0", severity: "error", file, line: Math.max(1, line), message, fix });
}

function hasBunfigCheat(raw: string): boolean {
  return auditBunfigContent(raw) !== null;
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
  const trackedSet = new Set(
    (runGitClean(repoPath, ["ls-files"]).stdout ?? "")
      .split(/\r?\n/)
      .map((s) => s.trim())
      .filter(Boolean),
  );
  const candidates = [".gitattributes", ".vstackignore", ".vstack.json", ".verification/vstack.json", "bunfig.toml", ".cargo/config.toml", ".cargo/config"];
  const findings: Finding[] = [];
  for (const rel of candidates) {
    if (trackedSet.has(rel)) continue;
    const lower = rel.toLowerCase();
    const abs = path.join(repoPath, rel);
    if (!fs.existsSync(abs) || !fs.statSync(abs).isFile()) continue;
    const raw = fs.readFileSync(abs, "utf8");
    if (lower === ".gitattributes") {
      if (/(?:^|\s)(?:-diff|binary|diff=)/i.test(raw)) pushDiff(findings, rel, 1, "diff-config-strictness-downgrade", "Untracked .gitattributes suppresses git diff (-diff/binary/diff=).", "Remove diff-suppressing .gitattributes rules.");
    } else if (lower === ".vstackignore") {
      const nonEmpty = raw.split(/\r?\n/).map((l) => l.trim()).filter((l) => l && !l.startsWith("#"));
      if (nonEmpty.length > 0) pushDiff(findings, rel, 1, "diff-config-strictness-downgrade", `Untracked .vstackignore excludes ${nonEmpty.length} path(s).`, "Remove untracked .vstackignore exclusions and fix findings directly.");
    } else if (lower === ".vstack.json" || lower === ".verification/vstack.json") {
      if (/(?:"off"|"info"|"disabledRules"|"ignore"\s*:\s*\[)/i.test(raw)) {
        pushDiff(findings, rel, 1, "diff-config-strictness-downgrade", `Untracked ${rel} disables, downgrades, or ignores Veristack rules.`, "Remove untracked Veristack suppression config and fix findings directly.");
      }
    } else if (lower === "bunfig.toml" && hasBunfigCheat(raw)) {
      pushDiff(findings, rel, 1, "diff-config-strictness-downgrade", "Untracked bunfig.toml adds preload hook or overrides [test].root.", "Remove preload hook / [test].root override from bunfig.toml.");
    } else if ((lower === ".cargo/config.toml" || lower === ".cargo/config") && /\b(?:runner|rustc-wrapper)\s*=/i.test(raw)) {
      pushDiff(findings, rel, 1, "diff-config-strictness-downgrade", `Untracked ${rel} overrides cargo runner/rustc-wrapper.`, `Remove runner/rustc-wrapper override from ${rel}.`);
    }
  }
  return findings;
}

export function auditDiffAntiEvasion(events: readonly DiffLineEvent[], _options: { migratedJsToTsFiles?: ReadonlySet<string> } = {}): Finding[] {
  const findings: Finding[] = [];
  const testAddedAsserts = new Map<string, number>();
  const testAddedWeakAsserts = new Map<string, number>();
  const testDeletedAsserts = new Map<string, { count: number; strictCount: number; firstLine: number }>();
  const delThresholds = new Map<string, Map<string, number>>();
  const addThresholds = new Map<string, Array<{ key: string; val: number; line: number }>>();
  const codeownersDelOwners = new Map<string, number>();
  const codeownersAddOwners = new Map<string, number>();
  const lawsDelCount = new Map<string, number>();
  const lawsAddCount = new Map<string, number>();
  const fileHasDel = new Set<string>();
  const fileHasAdd = new Set<string>();
  const addedCheckStepsByFile = new Map<string, number>();
  for (const ev of events) if (ev.kind === "add" && ev.file.toLowerCase().endsWith("package.json") && /"check"\s*:\s*"/.test(ev.raw)) addedCheckStepsByFile.set(ev.file, Math.max(addedCheckStepsByFile.get(ev.file) ?? 0, ev.raw.split("&&").length));

  for (const ev of events) {
    if (ev.kind === "del") fileHasDel.add(ev.file); else fileHasAdd.add(ev.file);
    const lower = ev.file.toLowerCase();
    const isWorkflow = /(?:^|\/)\.github\/workflows\/.+\.ya?ml$/i.test(lower);
    const isLawArtifact = /(?:^|\/)(?:\.verification\/laws\/|LAWS\.bend$|PROOF\.bend$|\.laws\.(?:json|bend)$)/i.test(ev.file);

    if (ev.kind === "add") {
      if (isLawArtifact && /(?:"id"\s*:|^\s*(?:law|theorem)\s+\w+)/.test(ev.raw)) lawsAddCount.set(ev.file, (lawsAddCount.get(ev.file) ?? 0) + 1);
      if (!TEST_FILE_PATH.test(ev.file) && /\bif\s*\(\s*false\s*&&/.test(ev.code)) pushDiff(findings, ev.file, ev.line, "diff-invariant-guard-weakened", "Added always-false short-circuit guard 'if (false && ...)' disabling a runtime check.", "Keep the runtime guard condition active instead of short-circuiting it with false.");
      if (lower.endsWith("lefthook.yml") && /^\s*run:\s*(?:true|:|echo\b|exit\s+0)\b/i.test(ev.raw)) pushDiff(findings, ev.file, ev.line, "diff-ci-safety-gate-removed", "Replaced lefthook verification hook with a no-op command in diff.", "Keep real verification commands in lefthook.yml.");
      if (/\.[cm]?[jt]sx?$/.test(lower)) {
        if (/\/\/\s*@ts-(?:ignore|nocheck)\b|\/\*\s*@ts-(?:ignore|nocheck)\b/.test(ev.raw)) pushDiff(findings, ev.file, ev.line, "diff-ts-suppression-added", "Added @ts-ignore/@ts-nocheck type-safety escape hatch in diff.", "Fix the underlying type error instead of disabling the TypeScript compiler.");
        else if (/\/\/\s*@ts-expect-error\s*$/.test(ev.raw)) pushDiff(findings, ev.file, ev.line, "diff-ts-suppression-added", "Added bare @ts-expect-error without a concrete justification in diff.", "Fix the type mismatch or document the exact invariant after @ts-expect-error.");
        else if (/(?:eslint|oxlint)-disable(?:-next-line|-line)?\s*(?:\*\/|$)|biome-ignore\s+[a-z0-9/]+\s*:?\s*(?:\*\/|$)/i.test(ev.raw)) pushDiff(findings, ev.file, ev.line, "diff-ts-suppression-added", "Added blanket linter suppression without reason in diff.", "Fix the lint finding instead of suppressing the linter.");
      }
      if (lower.endsWith(".go") && /\/\/\s*nolint(?:\s*$|\s*:[a-z0-9,-]+\s*$)/i.test(ev.raw)) pushDiff(findings, ev.file, ev.line, "diff-go-nolint-added", "Added unjustified //nolint directive in Go diff.", "Fix the linter issue or scope //nolint:<linter> with a concrete // justification.");
      if (isWorkflow) {
        if (/^\s*if:\s*(?:false|\$\{\{\s*false\s*\}\})\s*$/i.test(ev.raw)) pushDiff(findings, ev.file, ev.line, "diff-ci-safety-gate-removed", "Disabled CI job/step with 'if: false' in diff.", "Remove 'if: false' so CI gates execute unconditionally.");
        if (/^\s*(?:-\s*)?run:\s*(?:echo\b|true\b|:\s*$)/i.test(ev.raw) && events.some((o) => o.kind === "del" && o.file === ev.file && /\b(?:test|pytest|vitest|jest|cargo|go\s+test|dotnet\s+test|bun\s+test|vstack)\b/i.test(o.raw))) pushDiff(findings, ev.file, ev.line, "diff-ci-safety-gate-removed", "Replaced CI test/verification step with a no-op echo/true command in diff.", "Restore the real test/verification step.");
      }
      if (lower.endsWith("package.json") && (/"(?:test|check|lint|typecheck|verify)[^"]*"\s*:\s*"\s*(?:true|:|echo\b|exit\s+0)/i.test(ev.raw) || /"(?:preinstall|install|postinstall|prepare|preprepare|postprepare|prepublish|prepublishOnly|prepack|postpack)"\s*:/i.test(ev.raw))) pushDiff(findings, ev.file, ev.line, "diff-config-strictness-downgrade", "Modified package.json verification or install lifecycle script in diff.", "Keep verification scripts real and never add unreviewed install/prepare lifecycle hooks.");
      if (STRICT_CONFIG_PATH.test(ev.file)) {
        if (/"(?:strict|strictNullChecks|noImplicitAny|exactOptionalPropertyTypes)"\s*:\s*false/.test(ev.raw)) pushDiff(findings, ev.file, ev.line, "diff-config-strictness-downgrade", "Downgraded TypeScript strictness flag to false in config diff.", "Keep TypeScript strict compiler flags enabled.");
        if (lower.endsWith(".gitattributes") && /(?:^|\s)(?:-diff|binary|diff=)/i.test(ev.raw) && !ev.raw.trim().startsWith("#")) pushDiff(findings, ev.file, ev.line, "diff-config-strictness-downgrade", `Added diff-suppressing .gitattributes rule ('${ev.raw.trim()}').`, "Do not disable git diff on source or test files via .gitattributes.");
        if (lower.endsWith(".vstackignore") && ev.raw.trim().length > 0 && !ev.raw.trim().startsWith("#")) pushDiff(findings, ev.file, ev.line, "diff-config-strictness-downgrade", `Added new path exclusion ('${ev.raw.trim()}') to .vstackignore in diff.`, "Fix findings directly instead of excluding paths from verification.");
        if (/(?:oxlint|biome|ruff|mypy|clippy|golangci|pyproject\.toml|vstack\.json)/i.test(lower) && /(?:"off"|\bdisallow_untyped_defs\s*=\s*false|\bstrict\s*=\s*false|\bignore\s*=\s*\[|"disabledRules"\s*:|"ignore"\s*:\s*\[)/i.test(ev.raw)) pushDiff(findings, ev.file, ev.line, "diff-config-strictness-downgrade", "Relaxed linter/typechecker strictness rule in config diff.", "Keep strict lint/type rules enforced rather than disabling them in config.");
        if (/vstack\.json$/i.test(lower) && /:\s*"info"/i.test(ev.raw)) pushDiff(findings, ev.file, ev.line, "diff-config-strictness-downgrade", "Downgraded Veristack rule/category severity to 'info' in vstack.json diff.", "Keep rule severities intact instead of silencing them to 'info'.");
        if (/(?:pyproject\.toml|vitest\.config|vite\.config|jest\.config)/i.test(lower)) {
          for (const tm of ev.raw.matchAll(/\b(fail_under|lines|branches|functions|statements|thresholds)\s*[:=]\s*(\d+(?:\.\d+)?)/gi)) {
            const arr = addThresholds.get(ev.file) ?? []; arr.push({ key: (tm[1] ?? "").toLowerCase(), val: Number(tm[2]), line: ev.line }); addThresholds.set(ev.file, arr);
          }
        }
        if (lower.endsWith("codeowners") && /@[A-Za-z0-9_.-]+/.test(ev.raw) && !ev.raw.trim().startsWith("#")) codeownersAddOwners.set(ev.file, (codeownersAddOwners.get(ev.file) ?? 0) + 1);
      }
      if (TEST_FILE_PATH.test(ev.file) && ASSERT_CALL.test(ev.code)) {
        testAddedAsserts.set(ev.file, (testAddedAsserts.get(ev.file) ?? 0) + 1);
        if (WEAK_ASSERT.test(ev.code)) testAddedWeakAsserts.set(ev.file, (testAddedWeakAsserts.get(ev.file) ?? 0) + 1);
      }
    } else {
      if (isLawArtifact && /(?:"id"\s*:|^\s*(?:law|theorem)\s+\w+)/.test(ev.raw)) lawsDelCount.set(ev.file, (lawsDelCount.get(ev.file) ?? 0) + 1);
      if (lower.endsWith("package.json") && /"check"\s*:\s*"/.test(ev.raw) && (addedCheckStepsByFile.get(ev.file) ?? 0) < ev.raw.split("&&").length) pushDiff(findings, ev.file, ev.line, "diff-ci-safety-gate-removed", "Dropped verification step(s) from package.json 'check' script in diff.", "Keep all verification steps in the 'check' script.");
      if (isWorkflow && /^  [a-zA-Z0-9_-]+:\s*$/.test(ev.raw)) {
        const jobKey = ev.raw.trim();
        if (!events.some((o) => o.kind === "add" && o.file === ev.file && o.raw.trim() === jobKey)) pushDiff(findings, ev.file, ev.line, "diff-ci-safety-gate-removed", `Removed CI job '${jobKey.slice(0, -1)}' from ${ev.file} in diff.`, "Keep all verification jobs active in CI workflows.");
      }
      if (/tsconfig(?:\.[^/]+)?\.json$/i.test(lower) && /"(?:strict|strictNullChecks|noImplicitAny|exactOptionalPropertyTypes)"\s*:\s*true/.test(ev.raw)) {
        if (!events.some((o) => o.kind === "add" && o.file === ev.file && /"(?:strict|strictNullChecks|noImplicitAny|exactOptionalPropertyTypes)"\s*:\s*true/.test(o.raw))) pushDiff(findings, ev.file, ev.line, "diff-config-strictness-downgrade", "Removed TypeScript strictness flag from tsconfig in diff.", "Keep TypeScript strict compiler flags enabled.");
      }
      if (/(?:pyproject\.toml|vitest\.config|vite\.config|jest\.config)/i.test(lower)) {
        for (const tm of ev.raw.matchAll(/\b(fail_under|lines|branches|functions|statements|thresholds)\s*[:=]\s*(\d+(?:\.\d+)?)/gi)) {
          const map = delThresholds.get(ev.file) ?? new Map<string, number>(); const k = (tm[1] ?? "").toLowerCase(); map.set(k, Math.max(map.get(k) ?? 0, Number(tm[2]))); delThresholds.set(ev.file, map);
        }
      }
      if (lower.endsWith("codeowners") && /@[A-Za-z0-9_.-]+/.test(ev.raw) && !ev.raw.trim().startsWith("#")) codeownersDelOwners.set(ev.file, (codeownersDelOwners.get(ev.file) ?? 0) + 1);
      if (isWorkflow && /^\s*(?:pull_request|push)\s*:/i.test(ev.raw)) {
        const keptPrTrigger = events.some((o) => o.kind === "add" && o.file === ev.file && /^\s*(?:pull_request|push|merge_group)\s*:/i.test(o.raw));
        if (events.some((o) => o.kind === "add" && o.file === ev.file && /^\s*workflow_dispatch\s*:/i.test(o.raw)) && !keptPrTrigger) pushDiff(findings, ev.file, ev.line, "diff-ci-safety-gate-removed", "Changed PR-blocking workflow trigger to manual workflow_dispatch in diff.", "Keep pull_request/push triggers active on CI workflows.");
      }
      if (TEST_FILE_PATH.test(ev.file) && ASSERT_CALL.test(ev.code)) {
        const cur = testDeletedAsserts.get(ev.file) ?? { count: 0, strictCount: 0, firstLine: ev.line }; cur.count += 1; if (STRICT_ASSERT.test(ev.code)) cur.strictCount += 1; testDeletedAsserts.set(ev.file, cur);
      }
      const isCiOrHook = /(?:^|\/)(?:\.github\/workflows\/|lefthook\.yml|\.husky\/|package\.json)/i.test(ev.file);
      if (/\.verification\/invariants\.json$/i.test(ev.file) && /"kind"\s*:/.test(ev.raw)) pushDiff(findings, ev.file, ev.line, "diff-config-strictness-downgrade", "Deleted dynamic invariant entry from .verification/invariants.json in diff.", "Keep locked dynamic invariants intact.");
      if (isCiOrHook && GATE_TOOL_LINE.test(ev.raw) && !ev.raw.trim().startsWith("#")) {
        const hasMatchingAdd = events.some((other) => other.kind === "add" && other.file === ev.file && GATE_TOOL_LINE.test(other.raw) && sanitizeShellBlock(other.raw.replace(/^\s*(?:-\s*)?run:\s*/, "").trim()).length > 0);
        if (!hasMatchingAdd) pushDiff(findings, ev.file, ev.line, "diff-ci-safety-gate-removed", "Removed verification/linter gate from CI workflow or hook without an executable replacement.", "Keep verification gates active in CI and hooks.");
      }
    }
  }

  for (const [file, addedList] of addThresholds.entries()) {
    const delMap = delThresholds.get(file); if (!delMap) continue;
    for (const a of addedList) { const prev = delMap.get(a.key); if (prev !== undefined && a.val < prev) pushDiff(findings, file, a.line, "diff-config-strictness-downgrade", `Lowered coverage/quality threshold '${a.key}' from ${prev} to ${a.val} in ${file}.`, "Keep coverage and quality thresholds at or above the base branch floor."); }
  }
  for (const [file, delCount] of codeownersDelOwners.entries()) if (delCount > (codeownersAddOwners.get(file) ?? 0)) pushDiff(findings, file, 1, "diff-config-strictness-downgrade", `Removed ${delCount - (codeownersAddOwners.get(file) ?? 0)} CODEOWNERS protection rule(s) in ${file}.`, "Keep CODEOWNERS control-plane ownership intact.");
  for (const [file, delCount] of lawsDelCount.entries()) if (delCount > (lawsAddCount.get(file) ?? 0)) pushDiff(findings, file, 1, "diff-config-strictness-downgrade", `Removed ${delCount - (lawsAddCount.get(file) ?? 0)} declared law(s) from ${file}.`, "Keep declared laws intact; never prune laws to make checks pass.");
  for (const file of fileHasDel) if (!fileHasAdd.has(file) && /(?:^|\/)\.verification\/(?:control-plan\.json|rungs\.json|invariants\.json|laws\/[^/]+)$/i.test(file)) pushDiff(findings, file, 1, "diff-config-strictness-downgrade", `Deleted verification artifact '${file}' in diff.`, `Restore '${file}' instead of deleting verification control-plane artifacts.`);
  for (const [file, delInfo] of testDeletedAsserts.entries()) {
    const addedCount = testAddedAsserts.get(file) ?? 0; const weakAdded = testAddedWeakAsserts.get(file) ?? 0;
    if ((delInfo.count >= 2 && addedCount < delInfo.count) || (delInfo.strictCount >= 1 && addedCount < delInfo.count) || (delInfo.strictCount > 0 && weakAdded > 0 && addedCount <= delInfo.strictCount)) {
      pushDiff(findings, file, delInfo.firstLine, "diff-assertion-deleted", weakAdded > 0 && delInfo.strictCount > 0 ? `Weakened ${delInfo.strictCount} strict assertion(s) into existence-only assertion(s) in ${file}.` : `Net loss of test assertions in ${file} (deleted ${delInfo.count}, added ${addedCount}).`, "Preserve or strengthen exact behavioral assertions; never delete or dilute assertions to make a failing test pass.");
    }
  }
  return findings;
}

function collectReferencedScriptsAndFiles(
  commands: readonly string[],
  pkgScripts: Record<string, string>,
): { scripts: Set<string>; localScripts: Set<string>; subPkgRefs: Array<{ pkgRel: string; scriptName: string }> } {
  const scripts = new Set<string>();
  const localScripts = new Set<string>();
  const subPkgRefs: Array<{ pkgRel: string; scriptName: string }> = [];
  const queue = [...commands];
  for (let qi = 0; qi < queue.length; qi++) {
    const cmd = queue[qi] ?? "";
    for (const m of cmd.matchAll(/\bbun\s+--cwd\s+["']?([^\s"']+)["']?\s+(?:run\s+)?([A-Za-z0-9:_-]+)/g)) {
      const subDir = (m[1] ?? "").replace(/^\.\//, "").replace(/\/+$/, "");
      const name = m[2] ?? "";
      if (subDir && name) subPkgRefs.push({ pkgRel: `${subDir}/package.json`, scriptName: name });
    }
    for (const m of cmd.matchAll(/\bpnpm\s+(?:--filter|-F)\s+["']?([^\s"']+)["']?\s+(?:run\s+)?([A-Za-z0-9:_-]+)/g)) {
      const subDir = (m[1] ?? "").replace(/^\.\//, "").replace(/\/+$/, "");
      const name = m[2] ?? "";
      if (subDir && name && name !== "exec") subPkgRefs.push({ pkgRel: `${subDir}/package.json`, scriptName: name });
    }
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
    for (const m of cmd.matchAll(/\b(?:node|bun)\s+(?:\.\/)?(scripts\/[^\s"']+\.[cm]?[jt]s)/g)) {
      if (m[1]) localScripts.add(m[1]);
    }
  }
  return { scripts, localScripts, subPkgRefs };
}

const MONOTONIC_HIGHER_FLAGS = new Set(["--max-mutants", "--min-kill-rate", "--threshold-efficacy", "--cov-fail-under"]);
const MONOTONIC_LOWER_FLAGS = new Set(["--max-crap", "--max-time-exp", "--max-space-exp"]);
const TEST_PATH_ARG = /^(?:\.\/)?(?:tests?|__tests__|spec|specs|examples)\/\S*$/;

function stripBoundedTimeouts(tokens: string[]): string[] {
  const out: string[] = [];
  for (let i = 0; i < tokens.length; i++) {
    const t = tokens[i] ?? "";
    if (t === "--timeout" && i + 1 < tokens.length) {
      const n = Number(tokens[i + 1]);
      if (Number.isFinite(n) && n >= 5000 && n <= 60000) { i += 1; continue; }
    }
    out.push(t);
  }
  return out;
}

function tokenizeQuoted(cmd: string): string[] {
  const out: string[] = []; let cur = ""; let q: string | null = null;
  for (const ch of cmd.trim()) {
    if (q) { if (ch === q) q = null; else cur += ch; continue; }
    if (ch === "'" || ch === '"') { q = ch; continue; }
    if (/\s/.test(ch)) { if (cur) { out.push(cur); cur = ""; } continue; }
    cur += ch;
  }
  if (cur) out.push(cur);
  return out;
}

function isStrictCommandWeakening(baseCmd: string, headCmd: string): boolean {
  if (headCmd === baseCmd) return false;
  const bParts = baseCmd.split("&&").map((s) => s.trim()).filter(Boolean);
  const hParts = headCmd.split("&&").map((s) => s.trim()).filter(Boolean);
  if (hParts.length < bParts.length) return true;
  for (let p = 0; p < bParts.length; p++) {
    const bt = stripBoundedTimeouts(tokenizeQuoted(bParts[p] ?? ""));
    const ht = stripBoundedTimeouts(tokenizeQuoted(hParts[p] ?? ""));
    if (bt.length === 0 || ht.length === 0) return true;
    const bPos: string[] = []; const hPos: string[] = [];
    const bFlags = new Map<string, string>(); const hFlags = new Map<string, string>();
    const parse = (toks: string[], pos: string[], flags: Map<string, string>): string => {
      let i = 0;
      const head: string[] = [];
      while (i < toks.length && head.length < 3 && !(toks[i] ?? "").startsWith("-") && !TEST_PATH_ARG.test(toks[i] ?? "")) head.push(toks[i++] ?? "");
      for (; i < toks.length; i++) {
        const t = toks[i] ?? "";
        if (t.startsWith("-")) {
          const nxt = toks[i + 1];
          if (nxt !== undefined && !nxt.startsWith("-") && !TEST_PATH_ARG.test(nxt)) {
            flags.set(t, nxt); i += 1;
          } else flags.set(t, "1");
        } else pos.push(t);
      }
      return head.join(" ");
    };
    if (parse(bt, bPos, bFlags) !== parse(ht, hPos, hFlags)) return true;
    for (const [k, bv] of bFlags.entries()) {
      const hv = hFlags.get(k);
      if (hv === undefined) return true;
      if (hv === bv) continue;
      if (k === "--test-cmd") { if (isStrictCommandWeakening(bv, hv)) return true; continue; }
      if (k === "--targets") {
        const hs = new Set(hv.split(","));
        if (!bv.split(",").every((t) => hs.has(t))) return true;
        continue;
      }
      const bn = Number(bv); const hn = Number(hv);
      if (Number.isFinite(bn) && Number.isFinite(hn)) {
        if (MONOTONIC_HIGHER_FLAGS.has(k) && hn >= bn) continue;
        if (MONOTONIC_LOWER_FLAGS.has(k) && hn <= bn && hn > 0) continue;
      }
      return true;
    }
    for (const k of hFlags.keys()) if (!bFlags.has(k)) return true;
    if (bPos.length === 0 && hPos.length > 0) return true;
    const normP = (x: string): string => x.replace(/^\.\//, "");
    const covers = (hp: string, bp: string): boolean => normP(hp) === normP(bp) || (normP(hp).endsWith("/") && normP(bp).startsWith(normP(hp)));
    if (!bPos.every((bp) => hPos.some((hp) => covers(hp, bp)))) return true;
    if (!hPos.every((hp) => bPos.includes(hp) || TEST_PATH_ARG.test(hp))) return true;
  }
  return false;
}

const LIFECYCLE_SCRIPTS = ["preinstall", "install", "postinstall", "prepare", "preprepare", "postprepare", "prepublish", "prepublishOnly", "prepack", "postpack"];
const UNTRUSTED_SPEC_RE = /^(?:file:|link:|portal:|workspace:|\.\.?\/|\/|git\+|https?:|npm:|github:|gitlab:|bitbucket:|jsr:|[a-z0-9_.-]+\/[a-z0-9_.-]+(?:$|[#@]))|\.tgz$/i;

function collectToolDeps(pkg: Record<string, unknown>): Map<string, string> {
  const out = new Map<string, string>();
  const walkBag = (prefix: string, bag: unknown): void => {
    if (!bag || typeof bag !== "object" || Array.isArray(bag)) return;
    for (const [k, v] of Object.entries(bag as Record<string, unknown>)) {
      const tool = k.split("@")[0]?.toLowerCase() ?? k.toLowerCase();
      if (v && typeof v === "object" && !Array.isArray(v)) walkBag(`${prefix}.${k}`, v);
      else if (VERIFICATION_TOOLS.has(tool) && typeof v === "string") out.set(`${prefix}:${tool}`, v.trim());
    }
  };
  for (const bagKey of ["dependencies", "devDependencies", "optionalDependencies", "peerDependencies", "overrides", "resolutions", "patchedDependencies"]) walkBag(bagKey, pkg[bagKey]);
  if (pkg.pnpm && typeof pkg.pnpm === "object" && !Array.isArray(pkg.pnpm)) {
    const pnpm = pkg.pnpm as Record<string, unknown>;
    walkBag("pnpm.overrides", pnpm.overrides);
    walkBag("pnpm.patchedDependencies", pnpm.patchedDependencies);
  }
  return out;
}

function expandSubPkgScripts(scripts: Record<string, string>, rootName: string): Set<string> {
  const seen = new Set<string>();
  const q = [rootName];
  while (q.length > 0) {
    const name = q.pop() ?? "";
    if (!name || seen.has(name) || !scripts[name]) continue;
    seen.add(name);
    for (const h of [`pre${name}`, `post${name}`]) if (scripts[h] && !seen.has(h)) q.push(h);
    for (const m of (scripts[name] ?? "").matchAll(/\b(?:bun|npm|pnpm|yarn)\s+(?:run\s+)?([A-Za-z0-9:_-]+)/g)) if (m[1] && scripts[m[1]] && !seen.has(m[1])) q.push(m[1]);
  }
  return seen;
}

export function auditManifestDowngrade(repoRoot: string, baseRef: string, options: { failClosedOnMissingBase?: boolean; downgradeOnly?: boolean } = {}): Finding[] {
  const makeErr = (id: string, file: string, msg: string): Finding => ({
    id: `DIFF:manifest:${id}`, rule: "diff-manifest-downgrade", category: "cheat", rung: "R0", severity: "error", file, line: 1, message: msg,
    fix: "Keep or strengthen verification control-plane files; set VSTACK_ALLOW_MANIFEST_CHANGE=1 only for reviewed human upgrades.",
  });
  if (runGitClean(repoRoot, ["rev-parse", "--verify", `${baseRef}^{commit}`]).status !== 0) {
    return options.failClosedOnMissingBase ? [makeErr("missing-base", ".git", `Base ref '${baseRef}' could not be resolved for control-plane lock — failing closed.`)] : [];
  }
  const baseShow = runGitClean(repoRoot, ["show", `${baseRef}:.verification/rungs.json`]);
  if (baseShow.status !== 0) {
    return options.failClosedOnMissingBase && fs.existsSync(path.join(repoRoot, ".verification/rungs.json"))
      ? [makeErr("missing-base-manifest", ".verification/rungs.json", `Could not read .verification/rungs.json at base ref '${baseRef}'.`)]
      : [];
  }
  const headPath = path.join(repoRoot, ".verification/rungs.json");
  if (!fs.existsSync(headPath)) return [makeErr("deleted", ".verification/rungs.json", "Deleted .verification/rungs.json verification manifest compared to base branch.")];
  try {
    const base = JSON.parse(baseShow.stdout) as Partial<RungManifest>;
    const head = JSON.parse(fs.readFileSync(headPath, "utf8")) as Partial<RungManifest>;
    const findings: Finding[] = [];
    if (base.archetype && head.archetype && head.archetype !== base.archetype && head.archetype !== "fullstack") findings.push(makeErr("archetype", ".verification/rungs.json", `Changed manifest archetype '${base.archetype}' -> '${head.archetype}' vs ${baseRef}.`));
    const baseAllow = new Set(base.allowExcluded ?? []);
    for (const pat of head.allowExcluded ?? []) if (!baseAllow.has(pat)) findings.push(makeErr(`allow-${pat}`, ".verification/rungs.json", `Widened allowExcluded with '${pat}' vs ${baseRef}.`));
    const baseCmds: string[] = [];
    for (const [rung, baseEntry] of Object.entries(base.rungs ?? {})) {
      if (!baseEntry) continue;
      baseCmds.push(baseEntry.command);
      if (baseEntry.canary?.testCommand) baseCmds.push(baseEntry.canary.testCommand);
      const headEntry = head.rungs?.[rung as RungId];
      if (!headEntry) { findings.push(makeErr(`drop-${rung}`, ".verification/rungs.json", `Removed rung ${rung} from .verification/rungs.json vs ${baseRef}.`)); continue; }
      if (baseEntry.required !== false && headEntry.required === false) findings.push(makeErr(`req-${rung}`, ".verification/rungs.json", `Downgraded rung ${rung} required=true -> false vs ${baseRef}.`));
      if (options.downgradeOnly ? isStrictCommandWeakening(baseEntry.command, headEntry.command) : headEntry.command !== baseEntry.command) findings.push(makeErr(`cmd-${rung}`, ".verification/rungs.json", `Modified rung ${rung} verification command vs ${baseRef}.`));
      if (baseEntry.canary?.enabled && !headEntry.canary?.enabled) findings.push(makeErr(`canary-off-${rung}`, ".verification/rungs.json", `Disabled planted-fault canary on rung ${rung} vs ${baseRef}.`));
      if (baseEntry.canary?.enabled && headEntry.canary?.enabled) {
        if ((headEntry.canary.minKillRate ?? 0.8) < (baseEntry.canary.minKillRate ?? 0.8)) findings.push(makeErr(`canary-rate-${rung}`, ".verification/rungs.json", `Lowered canary minKillRate on ${rung} vs ${baseRef}.`));
        if ((headEntry.canary.maxMutants ?? 6) < (baseEntry.canary.maxMutants ?? 6)) findings.push(makeErr(`canary-mut-${rung}`, ".verification/rungs.json", `Lowered canary maxMutants on ${rung} vs ${baseRef}.`));
        const cBase = baseEntry.canary.testCommand ?? "";
        const cHead = headEntry.canary.testCommand ?? "";
        if (options.downgradeOnly ? isStrictCommandWeakening(cBase, cHead) : cHead !== cBase) findings.push(makeErr(`canary-cmd-${rung}`, ".verification/rungs.json", `Modified canary.testCommand on ${rung} vs ${baseRef}.`));
        const baseTargets = new Set(baseEntry.canary.targets ?? []);
        const headTargets = new Set(headEntry.canary.targets ?? []);
        for (const t of baseTargets) if (!headTargets.has(t)) findings.push(makeErr(`canary-target-${rung}-${t}`, ".verification/rungs.json", `Removed canary target '${t}' on ${rung} vs ${baseRef}.`));
        const addedTargets = headTargets.size - baseTargets.size;
        if (addedTargets > 0 && (!options.downgradeOnly || (headEntry.canary.maxMutants ?? 6) < (baseEntry.canary.maxMutants ?? 6) + addedTargets)) findings.push(makeErr(`canary-dilute-${rung}`, ".verification/rungs.json", `Added unreviewed canary target(s) on ${rung} vs ${baseRef} (risks diluting per-file mutation coverage).`));
      }
    }
    const headWsByPath = new Map((head.workspaces ?? []).map((h) => [h.path, h]));
    for (const ws of base.workspaces ?? []) {
      const hWs = headWsByPath.get(ws.path);
      if (!hWs) findings.push(makeErr(`ws-${ws.path}`, ".verification/rungs.json", `Removed workspace '${ws.path}' from .verification/rungs.json vs ${baseRef}.`));
      else if (ws.archetype && hWs.archetype && hWs.archetype !== ws.archetype && hWs.archetype !== "fullstack") findings.push(makeErr(`ws-arch-${ws.path}`, ".verification/rungs.json", `Changed workspace '${ws.path}' archetype '${ws.archetype}' -> '${hWs.archetype}' vs ${baseRef}.`));
    }
    const basePkgShow = runGitClean(repoRoot, ["show", `${baseRef}:package.json`]);
    const headPkgPath = path.join(repoRoot, "package.json");
    let baseScripts: Record<string, string> = {};
    if (basePkgShow.status === 0 && fs.existsSync(headPkgPath)) {
      try {
        const basePkg = JSON.parse(basePkgShow.stdout) as Record<string, unknown>;
        const headPkg = JSON.parse(fs.readFileSync(headPkgPath, "utf8")) as Record<string, unknown>;
        baseScripts = (basePkg.scripts as Record<string, string> | undefined) ?? {};
        const headScripts = (headPkg.scripts as Record<string, string> | undefined) ?? {};
        for (const sName of collectReferencedScriptsAndFiles(baseCmds, baseScripts).scripts) {
          if (options.downgradeOnly ? isStrictCommandWeakening(baseScripts[sName] ?? "", headScripts[sName] ?? "") : headScripts[sName] !== baseScripts[sName]) findings.push(makeErr(`pkg-script-${sName}`, "package.json", `Modified rung-referenced package.json script '${sName}' vs ${baseRef}.`));
        }
        for (const ls of LIFECYCLE_SCRIPTS) {
          if (headScripts[ls] !== baseScripts[ls]) findings.push(makeErr(`pkg-lifecycle-${ls}`, "package.json", `Added or modified package.json lifecycle script '${ls}' vs ${baseRef} (pre-verify ACE risk).`));
        }
        const baseTools = collectToolDeps(basePkg);
        const headTools = collectToolDeps(headPkg);
        for (const [k, bVal] of baseTools.entries()) {
          const hVal = headTools.get(k);
          if (hVal !== bVal && (!options.downgradeOnly || (hVal !== undefined && UNTRUSTED_SPEC_RE.test(hVal)))) findings.push(makeErr(`pkg-tool-${k}`, "package.json", `Modified verification tool dependency '${k}' in package.json vs ${baseRef}.`));
        }
        for (const [k, hVal] of headTools.entries()) {
          if (!baseTools.has(k) && (UNTRUSTED_SPEC_RE.test(hVal) || k.includes("patchedDependencies:"))) findings.push(makeErr(`pkg-tool-shadow-${k}`, "package.json", `Added untrusted/patched verification tool dependency '${k}=${hVal}' in package.json vs ${baseRef}.`));
        }
      } catch { findings.push(makeErr("pkg-json-invalid", "package.json", "Modified package.json is not valid JSON.")); }
    }
    const allRefs = collectReferencedScriptsAndFiles(baseCmds, baseScripts);
    for (const subRef of allRefs.subPkgRefs) {
      const baseSubShow = runGitClean(repoRoot, ["show", `${baseRef}:${subRef.pkgRel}`]);
      const headSubPath = path.join(repoRoot, subRef.pkgRel);
      if (baseSubShow.status === 0 && fs.existsSync(headSubPath)) {
        try {
          const bSub = (JSON.parse(baseSubShow.stdout) as { scripts?: Record<string, string> }).scripts ?? {};
          const hSub = (JSON.parse(fs.readFileSync(headSubPath, "utf8")) as { scripts?: Record<string, string> }).scripts ?? {};
          for (const expName of expandSubPkgScripts(bSub, subRef.scriptName)) {
            if (options.downgradeOnly ? isStrictCommandWeakening(bSub[expName] ?? "", hSub[expName] ?? "") : hSub[expName] !== bSub[expName]) findings.push(makeErr(`subpkg-${subRef.pkgRel}-${expName}`, subRef.pkgRel, `Modified rung-referenced sub-package script '${expName}' in ${subRef.pkgRel} vs ${baseRef}.`));
          }
        } catch { findings.push(makeErr(`subpkg-invalid-${subRef.pkgRel}`, subRef.pkgRel, `Modified ${subRef.pkgRel} is not valid JSON.`)); }
      }
    }
    for (const relScript of allRefs.localScripts) {
      const baseSc = runGitClean(repoRoot, ["show", `${baseRef}:${relScript}`]);
      const headScPath = path.join(repoRoot, relScript);
      if (baseSc.status === 0 && (!fs.existsSync(headScPath) || (!options.downgradeOnly && fs.readFileSync(headScPath, "utf8") !== baseSc.stdout))) findings.push(makeErr(`gate-script-${relScript}`, relScript, `Modified or deleted rung-referenced gate script '${relScript}' vs ${baseRef}.`));
    }
    if (!options.downgradeOnly) {
      const baseCpShow = runGitClean(repoRoot, ["show", `${baseRef}:.verification/control-plan.json`]);
      const headCpPath = path.join(repoRoot, ".verification/control-plan.json");
      if (baseCpShow.status === 0 && (!fs.existsSync(headCpPath) || fs.readFileSync(headCpPath, "utf8") !== baseCpShow.stdout)) findings.push(makeErr("control-plan", ".verification/control-plan.json", `Modified or deleted .verification/control-plan.json vs ${baseRef} (re-anchoring formal syncCommit requires reviewed control-plane approval).`));
    }
    const baseAttrShow = runGitClean(repoRoot, ["show", `${baseRef}:.gitattributes`]);
    const headAttrPath = path.join(repoRoot, ".gitattributes");
    if (fs.existsSync(headAttrPath)) {
      const headAttr = fs.readFileSync(headAttrPath, "utf8");
      if (headAttr !== (baseAttrShow.status === 0 ? baseAttrShow.stdout : "") && /(?:^|\s)(?:-diff|binary|diff=)/m.test(headAttr)) findings.push(makeErr("gitattributes", ".gitattributes", `Modified .gitattributes with diff-suppressing attribute (-diff/binary/diff=) vs ${baseRef}.`));
    }
    return findings;
  } catch { return [makeErr("invalid-json", ".verification/rungs.json", "Modified .verification/rungs.json is not valid JSON.")]; }
}
