import fs from "node:fs";
import path from "node:path";
import { sanitizeShellBlock } from "./command-audit.ts";
import { auditBunfigContent, runGitClean, VERIFICATION_TOOLS } from "./config-audit.ts";
import type { Finding, RungId, RungManifest } from "@veristack/plugin";

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

interface DiffCheatInput {
  file: string;
  line: number;
  rule: string;
  message: string;
  fix: string;
}

function pushDiff(findings: Finding[], entry: DiffCheatInput): void {
  findings.push({ id: `DIFF:${entry.rule}:${entry.file}:${entry.line}`, rule: entry.rule, category: "cheat", rung: "R0", severity: "error", file: entry.file, line: Math.max(1, entry.line), message: entry.message, fix: entry.fix });
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
  if (!repoPath) return [];
  const trackedSet = new Set((runGitClean(repoPath, ["ls-files"]).stdout ?? "").split(/\r?\n/).map((s) => s.trim()).filter(Boolean));
  const candidates = [".gitattributes", ".vstackignore", ".vstack.json", ".verification/vstack.json", "bunfig.toml", ".cargo/config.toml", ".cargo/config"];
  const findings: Finding[] = [];
  for (const rel of candidates) {
    if (trackedSet.has(rel)) continue;
    const lower = rel.toLowerCase();
    const abs = path.join(repoPath, rel);
    if (!fs.existsSync(abs) || !fs.statSync(abs).isFile()) continue;
    const raw = fs.readFileSync(abs, "utf8");
    if (lower === ".gitattributes" && /(?:^|\s)(?:-diff|binary|diff=)/i.test(raw)) {
      pushDiff(findings, { file: rel, line: 1, rule: "diff-config-strictness-downgrade", message: "Untracked .gitattributes suppresses git diff (-diff/binary/diff=).", fix: "Remove diff-suppressing .gitattributes rules." });
    } else if (lower === ".vstackignore") {
      const nonEmpty = raw.split(/\r?\n/).map((l) => l.trim()).filter((l) => l && !l.startsWith("#"));
      if (nonEmpty.length > 0) pushDiff(findings, { file: rel, line: 1, rule: "diff-config-strictness-downgrade", message: `Untracked .vstackignore excludes ${nonEmpty.length} path(s).`, fix: "Remove untracked .vstackignore exclusions and fix findings directly." });
    } else if ((lower === ".vstack.json" || lower === ".verification/vstack.json") && /(?:"off"|"info"|"disabledRules"|"ignore"\s*:\s*\[)/i.test(raw)) {
      pushDiff(findings, { file: rel, line: 1, rule: "diff-config-strictness-downgrade", message: `Untracked ${rel} disables, downgrades, or ignores Veristack rules.`, fix: "Remove untracked Veristack suppression config and fix findings directly." });
    } else if (lower === "bunfig.toml" && hasBunfigCheat(raw)) {
      pushDiff(findings, { file: rel, line: 1, rule: "diff-config-strictness-downgrade", message: "Untracked bunfig.toml adds preload hook or overrides [test].root.", fix: "Remove preload hook / [test].root override from bunfig.toml." });
    } else if ((lower === ".cargo/config.toml" || lower === ".cargo/config") && /\b(?:runner|rustc-wrapper)\s*=/i.test(raw)) {
      pushDiff(findings, { file: rel, line: 1, rule: "diff-config-strictness-downgrade", message: `Untracked ${rel} overrides cargo runner/rustc-wrapper.`, fix: `Remove runner/rustc-wrapper override from ${rel}.` });
    }
  }
  return findings;
}

interface DiffAuditState {
  findings: Finding[];
  testAddedAsserts: Map<string, number>;
  testAddedWeakAsserts: Map<string, number>;
  testDeletedAsserts: Map<string, { count: number; strictCount: number; firstLine: number }>;
  delThresholds: Map<string, Map<string, number>>;
  addThresholds: Map<string, Array<{ key: string; val: number; line: number }>>;
  codeownersDelOwners: Map<string, number>;
  codeownersAddOwners: Map<string, number>;
  lawsDelCount: Map<string, number>;
  lawsAddCount: Map<string, number>;
  addedCheckStepsByFile: Map<string, number>;
}

function auditAddedDiffEvent(ev: DiffLineEvent, events: readonly DiffLineEvent[], state: DiffAuditState): void {
  if (!ev.file) return;
  const lower = ev.file.toLowerCase();
  const isWorkflow = /(?:^|\/)\.github\/workflows\/.+\.ya?ml$/i.test(lower);
  const isLawArtifact = /(?:^|\/)(?:\.verification\/laws\/|LAWS\.bend$|PROOF\.bend$|\.laws\.(?:json|bend)$)/i.test(ev.file);
  if (isLawArtifact && /(?:"id"\s*:|^\s*(?:law|theorem)\s+\w+)/.test(ev.raw)) state.lawsAddCount.set(ev.file, (state.lawsAddCount.get(ev.file) ?? 0) + 1);
  if (!TEST_FILE_PATH.test(ev.file) && /\bif\s*\(\s*false\s*&&/.test(ev.code)) pushDiff(state.findings, { file: ev.file, line: ev.line, rule: "diff-invariant-guard-weakened", message: "Added always-false short-circuit guard 'if (false && ...)' disabling a runtime check.", fix: "Keep the runtime guard condition active instead of short-circuiting it with false." });
  if (lower.endsWith("lefthook.yml") && /^\s*run:\s*(?:true|:|echo\b|exit\s+0)\b/i.test(ev.raw)) pushDiff(state.findings, { file: ev.file, line: ev.line, rule: "diff-ci-safety-gate-removed", message: "Replaced lefthook verification hook with a no-op command in diff.", fix: "Keep real verification commands in lefthook.yml." });
  if (/\.[cm]?[jt]sx?$/.test(lower)) {
    if (/\/\/\s*@ts-(?:ignore|nocheck)\b|\/\*\s*@ts-(?:ignore|nocheck)\b/.test(ev.raw)) pushDiff(state.findings, { file: ev.file, line: ev.line, rule: "diff-ts-suppression-added", message: "Added @ts-ignore/@ts-nocheck type-safety escape hatch in diff.", fix: "Fix the underlying type error instead of disabling the TypeScript compiler." });
    else if (/\/\/\s*@ts-expect-error\s*$/.test(ev.raw)) pushDiff(state.findings, { file: ev.file, line: ev.line, rule: "diff-ts-suppression-added", message: "Added bare @ts-expect-error without a concrete justification in diff.", fix: "Fix the type mismatch or document the exact invariant after @ts-expect-error." });
    else if (/(?:eslint|oxlint)-disable(?:-next-line|-line)?\s*(?:\*\/|$)|biome-ignore\s+[a-z0-9/]+\s*:?\s*(?:\*\/|$)/i.test(ev.raw)) pushDiff(state.findings, { file: ev.file, line: ev.line, rule: "diff-ts-suppression-added", message: "Added blanket linter suppression without reason in diff.", fix: "Fix the lint finding instead of suppressing the linter." });
  }
  if (lower.endsWith(".go") && /\/\/\s*nolint(?:\s*$|\s*:[a-z0-9,-]+\s*$)/i.test(ev.raw)) pushDiff(state.findings, { file: ev.file, line: ev.line, rule: "diff-go-nolint-added", message: "Added unjustified //nolint directive in Go diff.", fix: "Fix the linter issue or scope //nolint:<linter> with a concrete // justification." });
  if (isWorkflow) {
    if (/^\s*if:\s*(?:false|\$\{\{\s*false\s*\}\})\s*$/i.test(ev.raw)) pushDiff(state.findings, { file: ev.file, line: ev.line, rule: "diff-ci-safety-gate-removed", message: "Disabled CI job/step with 'if: false' in diff.", fix: "Remove 'if: false' so CI gates execute unconditionally." });
    if (/^\s*(?:-\s*)?run:\s*(?:echo\b|true\b|:\s*$)/i.test(ev.raw) && events.some((o) => o.kind === "del" && o.file === ev.file && /\b(?:test|pytest|vitest|jest|cargo|go\s+test|dotnet\s+test|bun\s+test|vstack)\b/i.test(o.raw))) pushDiff(state.findings, { file: ev.file, line: ev.line, rule: "diff-ci-safety-gate-removed", message: "Replaced CI test/verification step with a no-op echo/true command in diff.", fix: "Restore the real test/verification step." });
  }
  if (lower.endsWith("package.json") && (/"(?:test|check|lint|typecheck|verify)[^"]*"\s*:\s*"\s*(?:true|:|echo\b|exit\s+0)/i.test(ev.raw) || /"(?:preinstall|install|postinstall|prepare|preprepare|postprepare|prepublish|prepublishOnly|prepack|postpack)"\s*:/i.test(ev.raw))) pushDiff(state.findings, { file: ev.file, line: ev.line, rule: "diff-config-strictness-downgrade", message: "Modified package.json verification or install lifecycle script in diff.", fix: "Keep verification scripts real and never add unreviewed install/prepare lifecycle hooks." });
  if (STRICT_CONFIG_PATH.test(ev.file)) {
    if (/"(?:strict|strictNullChecks|noImplicitAny|exactOptionalPropertyTypes)"\s*:\s*false/.test(ev.raw)) pushDiff(state.findings, { file: ev.file, line: ev.line, rule: "diff-config-strictness-downgrade", message: "Downgraded TypeScript strictness flag to false in config diff.", fix: "Keep TypeScript strict compiler flags enabled." });
    if (lower.endsWith(".gitattributes") && /(?:^|\s)(?:-diff|binary|diff=)/i.test(ev.raw) && !ev.raw.trim().startsWith("#")) pushDiff(state.findings, { file: ev.file, line: ev.line, rule: "diff-config-strictness-downgrade", message: `Added diff-suppressing .gitattributes rule ('${ev.raw.trim()}').`, fix: "Do not disable git diff on source or test files via .gitattributes." });
    if (lower.endsWith(".vstackignore") && ev.raw.trim().length > 0 && !ev.raw.trim().startsWith("#")) pushDiff(state.findings, { file: ev.file, line: ev.line, rule: "diff-config-strictness-downgrade", message: `Added new path exclusion ('${ev.raw.trim()}') to .vstackignore in diff.`, fix: "Fix findings directly instead of excluding paths from verification." });
    if (/(?:oxlint|biome|ruff|mypy|clippy|golangci|pyproject\.toml|vstack\.json)/i.test(lower) && /(?:"off"|\bdisallow_untyped_defs\s*=\s*false|\bstrict\s*=\s*false|\bignore\s*=\s*\[|"disabledRules"\s*:|"ignore"\s*:\s*\[)/i.test(ev.raw)) pushDiff(state.findings, { file: ev.file, line: ev.line, rule: "diff-config-strictness-downgrade", message: "Relaxed linter/typechecker strictness rule in config diff.", fix: "Keep strict lint/type rules enforced rather than disabling them in config." });
    if (/vstack\.json$/i.test(lower) && /:\s*"info"/i.test(ev.raw)) pushDiff(state.findings, { file: ev.file, line: ev.line, rule: "diff-config-strictness-downgrade", message: "Downgraded Veristack rule/category severity to 'info' in vstack.json diff.", fix: "Keep rule severities intact instead of silencing them to 'info'." });
    if (/(?:pyproject\.toml|vitest\.config|vite\.config|jest\.config)/i.test(lower)) {
      for (const tm of ev.raw.matchAll(/\b(fail_under|lines|branches|functions|statements|thresholds)\s*[:=]\s*(\d+(?:\.\d+)?)/gi)) {
        const arr = state.addThresholds.get(ev.file) ?? []; arr.push({ key: (tm[1] ?? "").toLowerCase(), val: Number(tm[2]), line: ev.line }); state.addThresholds.set(ev.file, arr);
      }
    }
    if (lower.endsWith("codeowners") && /@[A-Za-z0-9_.-]+/.test(ev.raw) && !ev.raw.trim().startsWith("#")) state.codeownersAddOwners.set(ev.file, (state.codeownersAddOwners.get(ev.file) ?? 0) + 1);
  }
  if (TEST_FILE_PATH.test(ev.file) && ASSERT_CALL.test(ev.code)) {
    state.testAddedAsserts.set(ev.file, (state.testAddedAsserts.get(ev.file) ?? 0) + 1);
    if (WEAK_ASSERT.test(ev.code)) state.testAddedWeakAsserts.set(ev.file, (state.testAddedWeakAsserts.get(ev.file) ?? 0) + 1);
  }
}

function auditDeletedDiffEvent(ev: DiffLineEvent, events: readonly DiffLineEvent[], state: DiffAuditState): void {
  if (!ev.file) return;
  const lower = ev.file.toLowerCase();
  const isWorkflow = /(?:^|\/)\.github\/workflows\/.+\.ya?ml$/i.test(lower);
  const isLawArtifact = /(?:^|\/)(?:\.verification\/laws\/|LAWS\.bend$|PROOF\.bend$|\.laws\.(?:json|bend)$)/i.test(ev.file);
  if (isLawArtifact && /(?:"id"\s*:|^\s*(?:law|theorem)\s+\w+)/.test(ev.raw)) state.lawsDelCount.set(ev.file, (state.lawsDelCount.get(ev.file) ?? 0) + 1);
  if (lower.endsWith("package.json") && /"check"\s*:\s*"/.test(ev.raw) && (state.addedCheckStepsByFile.get(ev.file) ?? 0) < ev.raw.split("&&").length) pushDiff(state.findings, { file: ev.file, line: ev.line, rule: "diff-ci-safety-gate-removed", message: "Dropped verification step(s) from package.json 'check' script in diff.", fix: "Keep all verification steps in the 'check' script." });
  if (isWorkflow && /^  [a-zA-Z0-9_-]+:\s*$/.test(ev.raw)) {
    const jobKey = ev.raw.trim();
    if (!events.some((o) => o.kind === "add" && o.file === ev.file && o.raw.trim() === jobKey)) pushDiff(state.findings, { file: ev.file, line: ev.line, rule: "diff-ci-safety-gate-removed", message: `Removed CI job '${jobKey.slice(0, -1)}' from ${ev.file} in diff.`, fix: "Keep all verification jobs active in CI workflows." });
  }
  if (/tsconfig(?:\.[^/]+)?\.json$/i.test(lower) && /"(?:strict|strictNullChecks|noImplicitAny|exactOptionalPropertyTypes)"\s*:\s*true/.test(ev.raw)) {
    if (!events.some((o) => o.kind === "add" && o.file === ev.file && /"(?:strict|strictNullChecks|noImplicitAny|exactOptionalPropertyTypes)"\s*:\s*true/.test(o.raw))) pushDiff(state.findings, { file: ev.file, line: ev.line, rule: "diff-config-strictness-downgrade", message: "Removed TypeScript strictness flag from tsconfig in diff.", fix: "Keep TypeScript strict compiler flags enabled." });
  }
  if (/(?:pyproject\.toml|vitest\.config|vite\.config|jest\.config)/i.test(lower)) {
    for (const tm of ev.raw.matchAll(/\b(fail_under|lines|branches|functions|statements|thresholds)\s*[:=]\s*(\d+(?:\.\d+)?)/gi)) {
      const map = state.delThresholds.get(ev.file) ?? new Map<string, number>(); map.set((tm[1] ?? "").toLowerCase(), Math.max(map.get((tm[1] ?? "").toLowerCase()) ?? 0, Number(tm[2]))); state.delThresholds.set(ev.file, map);
    }
  }
  if (lower.endsWith("codeowners") && /@[A-Za-z0-9_.-]+/.test(ev.raw) && !ev.raw.trim().startsWith("#")) state.codeownersDelOwners.set(ev.file, (state.codeownersDelOwners.get(ev.file) ?? 0) + 1);
  if (isWorkflow && /^\s*(?:pull_request|push)\s*:/i.test(ev.raw)) {
    const keptPrTrigger = events.some((o) => o.kind === "add" && o.file === ev.file && /^\s*(?:pull_request|push|merge_group)\s*:/i.test(o.raw));
    if (events.some((o) => o.kind === "add" && o.file === ev.file && /^\s*workflow_dispatch\s*:/i.test(o.raw)) && !keptPrTrigger) pushDiff(state.findings, { file: ev.file, line: ev.line, rule: "diff-ci-safety-gate-removed", message: "Changed PR-blocking workflow trigger to manual workflow_dispatch in diff.", fix: "Keep pull_request/push triggers active on CI workflows." });
  }
  if (TEST_FILE_PATH.test(ev.file) && ASSERT_CALL.test(ev.code)) {
    const cur = state.testDeletedAsserts.get(ev.file) ?? { count: 0, strictCount: 0, firstLine: ev.line }; cur.count += 1; if (STRICT_ASSERT.test(ev.code)) cur.strictCount += 1; state.testDeletedAsserts.set(ev.file, cur);
  }
  const isCiOrHook = /(?:^|\/)(?:\.github\/workflows\/|lefthook\.yml|\.husky\/|package\.json)/i.test(ev.file);
  if (/\.verification\/invariants\.json$/i.test(ev.file) && /"kind"\s*:/.test(ev.raw)) pushDiff(state.findings, { file: ev.file, line: ev.line, rule: "diff-config-strictness-downgrade", message: "Deleted dynamic invariant entry from .verification/invariants.json in diff.", fix: "Keep locked dynamic invariants intact." });
  if (isCiOrHook && GATE_TOOL_LINE.test(ev.raw) && !ev.raw.trim().startsWith("#")) {
    const hasMatchingAdd = events.some((other) => other.kind === "add" && other.file === ev.file && GATE_TOOL_LINE.test(other.raw) && sanitizeShellBlock(other.raw.replace(/^\s*(?:-\s*)?run:\s*/, "").trim()).length > 0);
    if (!hasMatchingAdd) pushDiff(state.findings, { file: ev.file, line: ev.line, rule: "diff-ci-safety-gate-removed", message: "Removed verification/linter gate from CI workflow or hook without an executable replacement.", fix: "Keep verification gates active in CI and hooks." });
  }
}

export function auditDiffAntiEvasion(events: readonly DiffLineEvent[], _options: { migratedJsToTsFiles?: ReadonlySet<string> } = {}): Finding[] {
  if (!Array.isArray(events)) throw new Error("events must be an array.");
  if (events.length === 0) return [];
  const state: DiffAuditState = {
    findings: [], testAddedAsserts: new Map(), testAddedWeakAsserts: new Map(), testDeletedAsserts: new Map(),
    delThresholds: new Map(), addThresholds: new Map(), codeownersDelOwners: new Map(), codeownersAddOwners: new Map(),
    lawsDelCount: new Map(), lawsAddCount: new Map(), addedCheckStepsByFile: new Map(),
  };
  const fileHasDel = new Set<string>(); const fileHasAdd = new Set<string>();
  for (const ev of events) if (ev.kind === "add" && ev.file.toLowerCase().endsWith("package.json") && /"check"\s*:\s*"/.test(ev.raw)) state.addedCheckStepsByFile.set(ev.file, Math.max(state.addedCheckStepsByFile.get(ev.file) ?? 0, ev.raw.split("&&").length));
  for (const ev of events) {
    if (ev.kind === "del") { fileHasDel.add(ev.file); auditDeletedDiffEvent(ev, events, state); }
    else { fileHasAdd.add(ev.file); auditAddedDiffEvent(ev, events, state); }
  }
  for (const [file, addedList] of state.addThresholds.entries()) {
    const delMap = state.delThresholds.get(file); if (!delMap) continue;
    for (const a of addedList) { const prev = delMap.get(a.key); if (prev !== undefined && a.val < prev) pushDiff(state.findings, { file, line: a.line, rule: "diff-config-strictness-downgrade", message: `Lowered coverage/quality threshold '${a.key}' from ${prev} to ${a.val} in ${file}.`, fix: "Keep coverage and quality thresholds at or above the base branch floor." }); }
  }
  for (const [file, delCount] of state.codeownersDelOwners.entries()) if (delCount > (state.codeownersAddOwners.get(file) ?? 0)) pushDiff(state.findings, { file, line: 1, rule: "diff-config-strictness-downgrade", message: `Removed ${delCount - (state.codeownersAddOwners.get(file) ?? 0)} CODEOWNERS protection rule(s) in ${file}.`, fix: "Keep CODEOWNERS control-plane ownership intact." });
  for (const [file, delCount] of state.lawsDelCount.entries()) if (delCount > (state.lawsAddCount.get(file) ?? 0)) pushDiff(state.findings, { file, line: 1, rule: "diff-config-strictness-downgrade", message: `Removed ${delCount - (state.lawsAddCount.get(file) ?? 0)} declared law(s) from ${file}.`, fix: "Keep declared laws intact; never prune laws to make checks pass." });
  for (const file of fileHasDel) if (!fileHasAdd.has(file) && /(?:^|\/)\.verification\/(?:control-plan\.json|rungs\.json|invariants\.json|laws\/[^/]+)$/i.test(file)) pushDiff(state.findings, { file, line: 1, rule: "diff-config-strictness-downgrade", message: `Deleted verification artifact '${file}' in diff.`, fix: `Restore '${file}' instead of deleting verification control-plane artifacts.` });
  for (const [file, delInfo] of state.testDeletedAsserts.entries()) {
    const addedCount = state.testAddedAsserts.get(file) ?? 0; const weakAdded = state.testAddedWeakAsserts.get(file) ?? 0;
    if ((delInfo.count >= 2 && addedCount < delInfo.count) || (delInfo.strictCount >= 1 && addedCount < delInfo.count) || (delInfo.strictCount > 0 && weakAdded > 0 && addedCount <= delInfo.strictCount)) {
      pushDiff(state.findings, { file, line: delInfo.firstLine, rule: "diff-assertion-deleted", message: weakAdded > 0 && delInfo.strictCount > 0 ? `Weakened ${delInfo.strictCount} strict assertion(s) into existence-only assertion(s) in ${file}.` : `Net loss of test assertions in ${file} (deleted ${delInfo.count}, added ${addedCount}).`, fix: "Preserve or strengthen exact behavioral assertions; never delete or dilute assertions to make a failing test pass." });
    }
  }
  return state.findings;
}

function collectReferencedScriptsAndFiles(
  commands: readonly string[],
  pkgScripts: Record<string, string>,
): { scripts: Set<string>; localScripts: Set<string>; subPkgRefs: Array<{ pkgRel: string; scriptName: string }> } {
  const scripts = new Set<string>();
  const localScripts = new Set<string>();
  const subPkgRefs: Array<{ pkgRel: string; scriptName: string }> = [];
  if (commands.length === 0) return { scripts, localScripts, subPkgRefs };
  const enqueueScript = (name: string): void => {
    if (!name || !pkgScripts[name] || scripts.has(name)) return;
    scripts.add(name); queue.push(pkgScripts[name] ?? "");
    for (const hook of [`pre${name}`, `post${name}`]) { if (pkgScripts[hook] && !scripts.has(hook)) { scripts.add(hook); queue.push(pkgScripts[hook] ?? ""); } }
  };
  const queue = [...commands];
  for (let qi = 0; qi < queue.length; qi++) {
    const cmd = queue[qi] ?? "";
    for (const m of cmd.matchAll(/\bbun\s+--cwd\s+["']?([^\s"']+)["']?\s+(?:run\s+)?([A-Za-z0-9:_-]+)/g)) {
      const subDir = (m[1] ?? "").replace(/^\.\//, "").replace(/\/+$/, "");
      if (subDir && m[2]) subPkgRefs.push({ pkgRel: `${subDir}/package.json`, scriptName: m[2] });
    }
    for (const m of cmd.matchAll(/\bpnpm\s+(?:--filter|-F)\s+["']?([^\s"']+)["']?\s+(?:run\s+)?([A-Za-z0-9:_-]+)/g)) {
      const subDir = (m[1] ?? "").replace(/^\.\//, "").replace(/\/+$/, "");
      if (subDir && m[2] && m[2] !== "exec") subPkgRefs.push({ pkgRel: `${subDir}/package.json`, scriptName: m[2] });
    }
    for (const m of cmd.matchAll(/\b(?:bun|npm|pnpm|yarn)\s+(?:run\s+)?([A-Za-z0-9:_-]+)/g)) enqueueScript(m[1] ?? "");
    for (const m of cmd.matchAll(/\b(?:node|bun)\s+(?:\.\/)?(scripts\/[^\s"']+\.[cm]?[jt]s)/g)) if (m[1]) localScripts.add(m[1]);
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

function parseCommandTokens(toks: string[]): { head: string; pos: string[]; flags: Map<string, string> } {
  let i = 0; const head: string[] = []; const pos: string[] = []; const flags = new Map<string, string>();
  while (i < toks.length && head.length < 3 && !(toks[i] ?? "").startsWith("-") && !TEST_PATH_ARG.test(toks[i] ?? "")) head.push(toks[i++] ?? "");
  for (; i < toks.length; i++) {
    const t = toks[i] ?? "";
    if (!t.startsWith("-")) { pos.push(t); continue; }
    const nxt = toks[i + 1];
    if (nxt !== undefined && !nxt.startsWith("-") && !TEST_PATH_ARG.test(nxt)) { flags.set(t, nxt); i += 1; } else flags.set(t, "1");
  }
  return { head: head.join(" "), pos, flags };
}

function isCommandPartWeakening(basePart: string, headPart: string, queue: Array<[string, string]>): boolean {
  const bt = stripBoundedTimeouts(tokenizeQuoted(basePart));
  const ht = stripBoundedTimeouts(tokenizeQuoted(headPart));
  if (bt.length === 0 || ht.length === 0) return true;
  const bParsed = parseCommandTokens(bt); const hParsed = parseCommandTokens(ht);
  if (bParsed.head !== hParsed.head) return true;
  for (const [k, bv] of bParsed.flags.entries()) {
    const hv = hParsed.flags.get(k);
    if (hv === undefined) return true;
    if (hv === bv) continue;
    if (k === "--test-cmd") { queue.push([bv, hv]); continue; }
    if (k === "--targets") { const hs = new Set(hv.split(",")); if (!bv.split(",").every((t) => hs.has(t))) return true; continue; }
    const bn = Number(bv); const hn = Number(hv);
    if (Number.isFinite(bn) && Number.isFinite(hn) && ((MONOTONIC_HIGHER_FLAGS.has(k) && hn >= bn) || (MONOTONIC_LOWER_FLAGS.has(k) && hn <= bn && hn > 0))) continue;
    return true;
  }
  for (const k of hParsed.flags.keys()) if (!bParsed.flags.has(k)) return true;
  if (bParsed.pos.length === 0 && hParsed.pos.length > 0) return true;
  const normP = (x: string): string => x.replace(/^\.\//, "");
  const covers = (hp: string, bp: string): boolean => normP(hp) === normP(bp) || (normP(hp).endsWith("/") && normP(bp).startsWith(normP(hp)));
  if (!bParsed.pos.every((bp) => hParsed.pos.some((hp) => covers(hp, bp)))) return true;
  return !hParsed.pos.every((hp) => bParsed.pos.includes(hp) || TEST_PATH_ARG.test(hp));
}

function isStrictCommandWeakening(baseCmd: string, headCmd: string): boolean {
  const queue: Array<[string, string]> = [[baseCmd, headCmd]];
  let iterations = 0;
  while (queue.length > 0 && ++iterations <= 32) {
    const pair = queue.pop();
    if (!pair || pair[1] === pair[0]) continue;
    const bParts = pair[0].split("&&").map((s) => s.trim()).filter(Boolean);
    const hParts = pair[1].split("&&").map((s) => s.trim()).filter(Boolean);
    if (hParts.length < bParts.length) return true;
    for (let p = 0; p < bParts.length; p++) {
      if (isCommandPartWeakening(bParts[p] ?? "", hParts[p] ?? "", queue)) return true;
    }
  }
  return false;
}

const LIFECYCLE_SCRIPTS = ["preinstall", "install", "postinstall", "prepare", "preprepare", "postprepare", "prepublish", "prepublishOnly", "prepack", "postpack"];
const UNTRUSTED_SPEC_RE = /^(?:file:|link:|portal:|workspace:|\.\.?\/|\/|git\+|https?:|npm:|github:|gitlab:|bitbucket:|jsr:|[a-z0-9_.-]+\/[a-z0-9_.-]+(?:$|[#@]))|\.tgz$/i;

function collectToolDeps(pkg: Record<string, unknown>): Map<string, string> {
  const out = new Map<string, string>();
  const stack: Array<{ prefix: string; bag: unknown }> = [];
  for (const bagKey of ["dependencies", "devDependencies", "optionalDependencies", "peerDependencies", "overrides", "resolutions", "patchedDependencies"]) stack.push({ prefix: bagKey, bag: pkg[bagKey] });
  if (pkg.pnpm && typeof pkg.pnpm === "object" && !Array.isArray(pkg.pnpm)) {
    const pnpm = pkg.pnpm as Record<string, unknown>;
    stack.push({ prefix: "pnpm.overrides", bag: pnpm.overrides }, { prefix: "pnpm.patchedDependencies", bag: pnpm.patchedDependencies });
  }
  while (stack.length > 0) {
    const cur = stack.pop();
    if (!cur?.bag || typeof cur.bag !== "object" || Array.isArray(cur.bag)) continue;
    for (const [k, v] of Object.entries(cur.bag as Record<string, unknown>)) {
      const tool = k.split("@")[0]?.toLowerCase() ?? k.toLowerCase();
      if (v && typeof v === "object" && !Array.isArray(v)) stack.push({ prefix: `${cur.prefix}.${k}`, bag: v });
      else if (VERIFICATION_TOOLS.has(tool) && typeof v === "string") out.set(`${cur.prefix}:${tool}`, v.trim());
    }
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

function makeManifestErr(id: string, file: string, msg: string): Finding {
  return { id: `DIFF:manifest:${id}`, rule: "diff-manifest-downgrade", category: "cheat", rung: "R0", severity: "error", file, line: 1, message: msg, fix: "Keep or strengthen verification control-plane files; set VSTACK_ALLOW_MANIFEST_CHANGE=1 only for reviewed human upgrades." };
}

function auditManifestRungsAndWorkspaces(
  base: Partial<RungManifest>,
  head: Partial<RungManifest>,
  opts: { baseRef: string; downgradeOnly?: boolean; findings: Finding[] },
): string[] {
  if (!opts.baseRef) throw new Error("baseRef is required.");
  const { baseRef, downgradeOnly, findings } = opts;
  if (base.archetype && head.archetype && head.archetype !== base.archetype && head.archetype !== "fullstack") findings.push(makeManifestErr("archetype", ".verification/rungs.json", `Changed manifest archetype '${base.archetype}' -> '${head.archetype}' vs ${baseRef}.`));
  const baseAllow = new Set(base.allowExcluded ?? []);
  for (const pat of head.allowExcluded ?? []) if (!baseAllow.has(pat)) findings.push(makeManifestErr(`allow-${pat}`, ".verification/rungs.json", `Widened allowExcluded with '${pat}' vs ${baseRef}.`));
  const baseCmds: string[] = [];
  for (const [rung, baseEntry] of Object.entries(base.rungs ?? {})) {
    if (!baseEntry) continue;
    baseCmds.push(baseEntry.command);
    if (baseEntry.canary?.testCommand) baseCmds.push(baseEntry.canary.testCommand);
    const headEntry = head.rungs?.[rung as RungId];
    if (!headEntry) { findings.push(makeManifestErr(`drop-${rung}`, ".verification/rungs.json", `Removed rung ${rung} from .verification/rungs.json vs ${baseRef}.`)); continue; }
    if (baseEntry.required !== false && headEntry.required === false) findings.push(makeManifestErr(`req-${rung}`, ".verification/rungs.json", `Downgraded rung ${rung} required=true -> false vs ${baseRef}.`));
    if (downgradeOnly ? isStrictCommandWeakening(baseEntry.command, headEntry.command) : headEntry.command !== baseEntry.command) findings.push(makeManifestErr(`cmd-${rung}`, ".verification/rungs.json", `Modified rung ${rung} verification command vs ${baseRef}.`));
    if (baseEntry.canary?.enabled && !headEntry.canary?.enabled) findings.push(makeManifestErr(`canary-off-${rung}`, ".verification/rungs.json", `Disabled planted-fault canary on rung ${rung} vs ${baseRef}.`));
    if (!baseEntry.canary?.enabled || !headEntry.canary?.enabled) continue;
    if ((headEntry.canary.minKillRate ?? 0.8) < (baseEntry.canary.minKillRate ?? 0.8)) findings.push(makeManifestErr(`canary-rate-${rung}`, ".verification/rungs.json", `Lowered canary minKillRate on ${rung} vs ${baseRef}.`));
    if ((headEntry.canary.maxMutants ?? 6) < (baseEntry.canary.maxMutants ?? 6)) findings.push(makeManifestErr(`canary-mut-${rung}`, ".verification/rungs.json", `Lowered canary maxMutants on ${rung} vs ${baseRef}.`));
    const cBase = baseEntry.canary.testCommand ?? ""; const cHead = headEntry.canary.testCommand ?? "";
    if (downgradeOnly ? isStrictCommandWeakening(cBase, cHead) : cHead !== cBase) findings.push(makeManifestErr(`canary-cmd-${rung}`, ".verification/rungs.json", `Modified canary.testCommand on ${rung} vs ${baseRef}.`));
    const baseTargets = new Set(baseEntry.canary.targets ?? []); const headTargets = new Set(headEntry.canary.targets ?? []);
    for (const t of baseTargets) if (!headTargets.has(t)) findings.push(makeManifestErr(`canary-target-${rung}-${t}`, ".verification/rungs.json", `Removed canary target '${t}' on ${rung} vs ${baseRef}.`));
    const addedTargets = headTargets.size - baseTargets.size;
    if (addedTargets > 0 && (!downgradeOnly || (headEntry.canary.maxMutants ?? 6) < (baseEntry.canary.maxMutants ?? 6) + addedTargets)) findings.push(makeManifestErr(`canary-dilute-${rung}`, ".verification/rungs.json", `Added unreviewed canary target(s) on ${rung} vs ${baseRef} (risks diluting per-file mutation coverage).`));
  }
  const headWsByPath = new Map((head.workspaces ?? []).map((h) => [h.path, h]));
  for (const ws of base.workspaces ?? []) {
    const hWs = headWsByPath.get(ws.path);
    if (!hWs) findings.push(makeManifestErr(`ws-${ws.path}`, ".verification/rungs.json", `Removed workspace '${ws.path}' from .verification/rungs.json vs ${baseRef}.`));
    else if (ws.archetype && hWs.archetype && hWs.archetype !== ws.archetype && hWs.archetype !== "fullstack") findings.push(makeManifestErr(`ws-arch-${ws.path}`, ".verification/rungs.json", `Changed workspace '${ws.path}' archetype '${ws.archetype}' -> '${hWs.archetype}' vs ${baseRef}.`));
  }
  return baseCmds;
}

function auditPackageAndControlPlane(
  repoRoot: string,
  baseCmds: readonly string[],
  opts: { baseRef: string; downgradeOnly?: boolean; findings: Finding[] },
): void {
  if (!repoRoot) throw new Error("repoRoot is required.");
  const { baseRef, downgradeOnly, findings } = opts;
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
        if (downgradeOnly ? isStrictCommandWeakening(baseScripts[sName] ?? "", headScripts[sName] ?? "") : headScripts[sName] !== baseScripts[sName]) findings.push(makeManifestErr(`pkg-script-${sName}`, "package.json", `Modified rung-referenced package.json script '${sName}' vs ${baseRef}.`));
      }
      for (const ls of LIFECYCLE_SCRIPTS) if (headScripts[ls] !== baseScripts[ls]) findings.push(makeManifestErr(`pkg-lifecycle-${ls}`, "package.json", `Added or modified package.json lifecycle script '${ls}' vs ${baseRef} (pre-verify ACE risk).`));
      const baseTools = collectToolDeps(basePkg); const headTools = collectToolDeps(headPkg);
      for (const [k, bVal] of baseTools.entries()) {
        const hVal = headTools.get(k);
        if (hVal !== bVal && (!downgradeOnly || (hVal !== undefined && UNTRUSTED_SPEC_RE.test(hVal)))) findings.push(makeManifestErr(`pkg-tool-${k}`, "package.json", `Modified verification tool dependency '${k}' in package.json vs ${baseRef}.`));
      }
      for (const [k, hVal] of headTools.entries()) if (!baseTools.has(k) && (UNTRUSTED_SPEC_RE.test(hVal) || k.includes("patchedDependencies:"))) findings.push(makeManifestErr(`pkg-tool-shadow-${k}`, "package.json", `Added untrusted/patched verification tool dependency '${k}=${hVal}' in package.json vs ${baseRef}.`));
    } catch { findings.push(makeManifestErr("pkg-json-invalid", "package.json", "Modified package.json is not valid JSON.")); }
  }
  const allRefs = collectReferencedScriptsAndFiles(baseCmds, baseScripts);
  for (const subRef of allRefs.subPkgRefs) {
    const baseSubShow = runGitClean(repoRoot, ["show", `${baseRef}:${subRef.pkgRel}`]);
    const headSubPath = path.join(repoRoot, subRef.pkgRel);
    if (baseSubShow.status !== 0 || !fs.existsSync(headSubPath)) continue;
    try {
      const bSub = (JSON.parse(baseSubShow.stdout) as { scripts?: Record<string, string> }).scripts ?? {};
      const hSub = (JSON.parse(fs.readFileSync(headSubPath, "utf8")) as { scripts?: Record<string, string> }).scripts ?? {};
      for (const expName of expandSubPkgScripts(bSub, subRef.scriptName)) {
        if (downgradeOnly ? isStrictCommandWeakening(bSub[expName] ?? "", hSub[expName] ?? "") : hSub[expName] !== bSub[expName]) findings.push(makeManifestErr(`subpkg-${subRef.pkgRel}-${expName}`, subRef.pkgRel, `Modified rung-referenced sub-package script '${expName}' in ${subRef.pkgRel} vs ${baseRef}.`));
      }
    } catch { findings.push(makeManifestErr(`subpkg-invalid-${subRef.pkgRel}`, subRef.pkgRel, `Modified ${subRef.pkgRel} is not valid JSON.`)); }
  }
  for (const relScript of allRefs.localScripts) {
    const baseSc = runGitClean(repoRoot, ["show", `${baseRef}:${relScript}`]);
    const headScPath = path.join(repoRoot, relScript);
    if (baseSc.status === 0 && (!fs.existsSync(headScPath) || (!downgradeOnly && fs.readFileSync(headScPath, "utf8") !== baseSc.stdout))) findings.push(makeManifestErr(`gate-script-${relScript}`, relScript, `Modified or deleted rung-referenced gate script '${relScript}' vs ${baseRef}.`));
  }
  if (!downgradeOnly) {
    const baseCpShow = runGitClean(repoRoot, ["show", `${baseRef}:.verification/control-plan.json`]);
    const headCpPath = path.join(repoRoot, ".verification/control-plan.json");
    if (baseCpShow.status === 0 && (!fs.existsSync(headCpPath) || fs.readFileSync(headCpPath, "utf8") !== baseCpShow.stdout)) findings.push(makeManifestErr("control-plan", ".verification/control-plan.json", `Modified or deleted .verification/control-plan.json vs ${baseRef} (re-anchoring formal syncCommit requires reviewed control-plane approval).`));
  }
  const baseAttrShow = runGitClean(repoRoot, ["show", `${baseRef}:.gitattributes`]);
  const headAttrPath = path.join(repoRoot, ".gitattributes");
  if (fs.existsSync(headAttrPath)) {
    const headAttr = fs.readFileSync(headAttrPath, "utf8");
    if (headAttr !== (baseAttrShow.status === 0 ? baseAttrShow.stdout : "") && /(?:^|\s)(?:-diff|binary|diff=)/m.test(headAttr)) findings.push(makeManifestErr("gitattributes", ".gitattributes", `Modified .gitattributes with diff-suppressing attribute (-diff/binary/diff=) vs ${baseRef}.`));
  }
}

export function auditManifestDowngrade(repoRoot: string, baseRef: string, options: { failClosedOnMissingBase?: boolean; downgradeOnly?: boolean } = {}): Finding[] {
  if (runGitClean(repoRoot, ["rev-parse", "--verify", `${baseRef}^{commit}`]).status !== 0) {
    return options.failClosedOnMissingBase ? [makeManifestErr("missing-base", ".git", `Base ref '${baseRef}' could not be resolved for control-plane lock — failing closed.`)] : [];
  }
  const baseShow = runGitClean(repoRoot, ["show", `${baseRef}:.verification/rungs.json`]);
  if (baseShow.status !== 0) {
    return options.failClosedOnMissingBase && fs.existsSync(path.join(repoRoot, ".verification/rungs.json"))
      ? [makeManifestErr("missing-base-manifest", ".verification/rungs.json", `Could not read .verification/rungs.json at base ref '${baseRef}'.`)]
      : [];
  }
  const headPath = path.join(repoRoot, ".verification/rungs.json");
  if (!fs.existsSync(headPath)) return [makeManifestErr("deleted", ".verification/rungs.json", "Deleted .verification/rungs.json verification manifest compared to base branch.")];
  try {
    const base = JSON.parse(baseShow.stdout) as Partial<RungManifest>;
    const head = JSON.parse(fs.readFileSync(headPath, "utf8")) as Partial<RungManifest>;
    const findings: Finding[] = [];
    const baseCmds = auditManifestRungsAndWorkspaces(base, head, { baseRef, downgradeOnly: options.downgradeOnly, findings });
    auditPackageAndControlPlane(repoRoot, baseCmds, { baseRef, downgradeOnly: options.downgradeOnly, findings });
    return findings;
  } catch { return [makeManifestErr("invalid-json", ".verification/rungs.json", "Modified .verification/rungs.json is not valid JSON.")]; }
}
