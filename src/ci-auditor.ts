import fs from "node:fs";
import path from "node:path";
import { detectLanguage, type DiscoveredRepo, isTestFilePath } from "./discover.ts";
import { auditDiffInvariantLoss } from "./ast/invariant-loss.ts";
import { runGitClean } from "./rungs/config-audit.ts";
import { maskCode } from "./test-lexical.ts";
import type { Finding } from "./types.ts";
import {
  auditDiffAntiEvasion,
  auditManifestDowngrade,
  type DiffLineEvent,
  normalizeDiffMigrationPairs,
  scanUntrackedConfigCheats,
} from "./zero-defect/anti-evasion.ts";
import { auditExtendedCiRules, auditMaestroFlow } from "./zero-defect/ci-workflow-rules.ts";

const RUNNER_TEST_BASENAME = /(?:\.(?:test|spec|e2e|cy)\.[cm]?[jt]sx?$|_test\.go$|_tests?\.rs$|(?:^|\/)test_[^/]+\.py$|_test\.py$|tests?\.cs$)/i;

function isRunnerDiscoveredTest(rel: string): boolean {
  return RUNNER_TEST_BASENAME.test(rel);
}

const CHECK_TOOL =
  /\b(?:pnpm|npm|yarn|npx|bun|pytest|vitest|jest|tsc|tsgo|eslint|oxlint|prettier|ruff|mypy|cargo|go|make|gradle|mvn|dotnet|unittest|vstack)\b/i;

const WORKFLOW_CHEATS: ReadonlyArray<{ rule: string; regex: RegExp; severity: Finding["severity"]; message: string; fix: string }> = [
  { rule: "ci-continue-on-error", regex: /continue-on-error:\s*true/i, severity: "error", message: "Workflow sets continue-on-error: true, silently hiding failures.", fix: "Remove continue-on-error: true so failing checks block merges." },
  { rule: "ci-pull-request-target", regex: /\bpull_request_target\b/, severity: "error", message: "pull_request_target exposes repository secrets/write access to untrusted PRs.", fix: "Use pull_request trigger with minimal read-only permissions." },
  { rule: "ci-wide-permissions", regex: /permissions:\s*write-all|\bcontents:\s*write\b/, severity: "error", message: "Workflow grants overly wide write permissions.", fix: "Restrict permissions to contents: read and grant narrow scopes only to release jobs." },
  { rule: "ci-retry-action", regex: /\bnick-fields\/retry\b|\b--reruns\b|\bretry-attempts\b/i, severity: "error", message: "CI step retries failed commands, masking flaky tests.", fix: "Remove CI retries and fix the underlying flake deterministically." },
  { rule: "ci-excessive-timeout", regex: /timeout-minutes:\s*\d{3,}/, severity: "warn", message: "Workflow timeout >= 100 minutes hides hangs and burns runner budget.", fix: "Lower timeout-minutes to match the actual critical path (typically 5–20m)." },
  { rule: "ci-pipe-tail-head", regex: /\|\s*(?:tail|head)\b/, severity: "error", message: "Piping a check command into tail/head masks non-zero exit codes without pipefail.", fix: "Write command output to a log file and read the file instead of piping." },
];

export function auditCiWorkflows(repo: DiscoveredRepo): Finding[] {
  const findings: Finding[] = [];

  for (const file of repo.files) {
    if (!file.isWorkflow) {
      findings.push(...auditMaestroFlow(file));
      continue;
    }
    const lines = file.content.split(/\r?\n/);

    const isGeneratedAgentLock = /\.lock\.ya?ml$/i.test(file.rel) && !/^\s*(?:pull_request|merge_group)\s*:/m.test(file.content);
    for (let idx = 0; idx < lines.length; idx++) {
      const raw = lines[idx] ?? "";
      const stripped = raw.replace(/\s+#.*$/, "");
      if (!stripped.trim() || /^\s*#/.test(raw)) continue;

      if (/\|\|\s*(?:true\b|:)/.test(stripped) && CHECK_TOOL.test(stripped)) {
        findings.push({
          id: `CI:swallowed:${file.rel}:${idx + 1}`,
          rule: "ci-swallowed-failure",
          category: "cheat",
          rung: "R0",
          severity: "error",
          file: file.rel,
          line: idx + 1,
          message: "Check command followed by '|| true' swallows failures.",
          fix: "Remove '|| true' so the job fails when the check fails.",
        });
      }

      for (const rule of WORKFLOW_CHEATS) {
        if (!rule.regex.test(stripped)) continue;
        if (rule.rule === "ci-pipe-tail-head" && !CHECK_TOOL.test(stripped)) continue;
        if (rule.rule === "ci-continue-on-error" && isGeneratedAgentLock) continue;
        findings.push({
          id: `CI:${rule.rule}:${file.rel}:${idx + 1}`,
          rule: rule.rule,
          category: rule.severity === "error" ? "cheat" : "ci-hygiene",
          rung: "R0",
          severity: rule.severity,
          file: file.rel,
          line: idx + 1,
          message: rule.message,
          fix: rule.fix,
        });
      }
    }

    if (file.rel.startsWith(".github/workflows/")) {
      if (!/^\s*concurrency:/m.test(file.content)) {
        findings.push({
          id: `CI:missing-concurrency:${file.rel}`,
          rule: "ci-missing-concurrency",
          category: "ci-hygiene",
          rung: "R6",
          severity: "warn",
          file: file.rel,
          line: 1,
          message: "Workflow lacks a concurrency group; superseded PR pushes keep burning minutes.",
          fix: "Add concurrency: { group: ${{ github.workflow }}-${{ github.ref }}, cancel-in-progress: true }.",
        });
      }

      if (/^\s*jobs:/m.test(file.content) && !/timeout-minutes:\s*\d+/.test(file.content)) {
        findings.push({
          id: `CI:missing-timeout:${file.rel}`,
          rule: "ci-missing-timeout",
          category: "ci-hygiene",
          rung: "R6",
          severity: "warn",
          file: file.rel,
          line: 1,
          message: "Workflow omits timeout-minutes; hung jobs default to 6 hours and burn runner minutes.",
          fix: "Set explicit timeout-minutes (e.g. 10-20) on every job matching its critical path.",
        });
      }

      if (/fetch-depth:\s*0/.test(file.content)) {
        findings.push({
          id: `CI:full-clone:${file.rel}`,
          rule: "ci-full-clone",
          category: "ci-hygiene",
          rung: "R6",
          severity: "warn",
          file: file.rel,
          line: 1,
          message: "fetch-depth: 0 clones full git history on every run.",
          fix: "Use shallow/blobless checkout unless full history is strictly required for this job.",
        });
      }

      if (/^\s*paths:/m.test(file.content)) {
        findings.push({
          id: `CI:paths-filter:${file.rel}`,
          rule: "ci-paths-on-required-check",
          category: "ci-hygiene",
          rung: "R6",
          severity: "info",
          file: file.rel,
          line: 1,
          message: "Workflow uses paths: filter — if any job here is a required status check, skipped PRs will stay pending forever.",
          fix: "Ensure required status checks always report, or move path filtering inside a gating job with fail-closed fallback.",
        });
      }
    }

    findings.push(...auditExtendedCiRules(file));
  }

  return findings;
}

export function scanGitDiffCheats(repoPath: string, baseRef = "HEAD"): Finding[] {
  if (!baseRef || baseRef.startsWith("-")) {
    throw new Error(`Invalid git baseRef "${baseRef}".`);
  }
  const diff = runGitClean(repoPath, ["diff", "--text", "--no-ext-diff", "--no-textconv", "-M20%", baseRef, "--unified=0", "--no-color"]);
  if (diff.status !== 0) {
    return [
      {
        id: `DIFF:git-diff-failed:${baseRef}`,
        rule: "diff-command-failed",
        category: "cheat",
        rung: "R0",
        severity: "error",
        file: ".git",
        line: 1,
        message: `git diff ${baseRef} failed (exit ${diff.status ?? 1}): ${(diff.stderr ?? "").trim() || "unknown git error"} — failing closed.`,
        fix: `Ensure git ref '${baseRef}' exists in this checkout (fetch base ref in CI) before running diff-cheats.`,
      },
    ];
  }

  const findings: Finding[] = [];
  const diffEvents: DiffLineEvent[] = [];
  const renamedJsToTsFiles = new Set<string>();
  const deletedFiles: string[] = [];
  let prevOldFile = "";
  let renameFrom = "";
  let currentFile = "<diff>";
  let currentLine = 1;
  let delLine = 1;

  const maskedCache = new Map<string, string[] | null>();
  const getMaskedLine = (rel: string, lineNum: number, fallback: string): string => {
    let lines = maskedCache.get(rel);
    if (lines === undefined) {
      const fullPath = path.resolve(repoPath, rel);
      try {
        const rawText = fs.readFileSync(fullPath, "utf8");
        lines = maskCode(rawText, detectLanguage(rel)).split(/\r?\n/);
      } catch {
        lines = null;
      }
      maskedCache.set(rel, lines);
    }
    if (!lines) return fallback;
    return lines[lineNum - 1] ?? fallback;
  };

  const baseMaskedCache = new Map<string, string[] | null>();
  const getBaseMaskedLine = (rel: string, lineNum: number, fallback: string): string => {
    let lines = baseMaskedCache.get(rel);
    if (lines === undefined) {
      const show = runGitClean(repoPath, ["show", `${baseRef}:${rel}`], { maxBuffer: 8 * 1024 * 1024 });
      lines = show.status === 0 ? maskCode(show.stdout, detectLanguage(rel)).split(/\r?\n/) : null;
      baseMaskedCache.set(rel, lines);
    }
    if (!lines) return fallback;
    return lines[lineNum - 1] ?? fallback;
  };

  for (const raw of diff.stdout.split(/\r?\n/)) {
    const hdr = /^diff --git a\/(.+?) b\/(.+)$/.exec(raw);
    if (hdr) {
      prevOldFile = hdr[1] ?? "";
      currentFile = hdr[2] ?? "<diff>";
      renameFrom = "";
      continue;
    }
    if (raw.startsWith("rename from ")) {
      renameFrom = raw.slice(12).trim();
      continue;
    }
    if (raw.startsWith("rename to ")) {
      const renameTo = raw.slice(10).trim();
      const jsStem = /^(.+)\.([cm]?)js(x?)$/i.exec(renameFrom);
      if (jsStem && renameTo === `${jsStem[1]}.${jsStem[2]}ts${jsStem[3]}`) {
        renamedJsToTsFiles.add(renameTo);
      }
      if (renameFrom && ((isTestFilePath(renameFrom) && !isTestFilePath(renameTo)) || (isRunnerDiscoveredTest(renameFrom) && !isRunnerDiscoveredTest(renameTo)))) {
        findings.push({
          id: `DIFF:test-renamed-out:${renameFrom}`,
          rule: "diff-test-file-deleted",
          category: "cheat",
          rung: "R0",
          severity: "error",
          file: renameTo,
          line: 1,
          message: `Test file '${renameFrom}' was renamed out of test discovery to '${renameTo}'.`,
          fix: "Keep test files matching test discovery globs so they stay executed in CI.",
        });
      }
      renameFrom = "";
      continue;
    }
    if (raw.startsWith("--- a/")) {
      prevOldFile = raw.slice(6);
      continue;
    }
    if (raw === "+++ /dev/null") {
      if (prevOldFile) deletedFiles.push(prevOldFile);
      currentFile = prevOldFile || "<diff>";
      continue;
    }
    if (raw.startsWith("+++ b/")) {
      currentFile = raw.slice(6);
      continue;
    }
    const hunk = /^@@ -(\d+)(?:,\d+)? \+(\d+)/.exec(raw);
    if (hunk) {
      delLine = Math.max(1, Number(hunk[1]));
      currentLine = Math.max(1, Number(hunk[2]));
      continue;
    }
    if (raw.startsWith("-") && !raw.startsWith("---")) {
      const removed = raw.slice(1);
      const lowerCur = currentFile.toLowerCase();
      if (!/\.(?:md|mdx|txt|rst)$/.test(lowerCur)) {
        const delCode = /\.(?:cs|rs|[cm]?[jt]sx?|py|go)$/.test(lowerCur)
          ? getBaseMaskedLine(currentFile, delLine, removed)
          : removed;
        diffEvents.push({ file: currentFile, line: delLine, kind: "del", raw: removed, code: delCode });
      }
      delLine += 1;
      continue;
    }
    if (!raw.startsWith("+") || raw.startsWith("+++")) continue;
    const added = raw.slice(1);
    const stripped = added.replace(/\s+#.*$/, "");
    const lowerFile = currentFile.toLowerCase();
    const isDocFile = /\.(?:md|mdx|txt|rst)$/.test(lowerFile);
    const isWorkflowOrScript =
      /(?:^|\/)(?:\.github\/workflows\/|\.gitlab-ci|azure-pipelines|makefile|lefthook\.yml|package\.json)|(?:\.ya?ml|\.sh|\.bash|\.zsh|\.ps1)$/.test(
        lowerFile,
      );

    if (isDocFile) {
      currentLine += 1;
      continue;
    }

    const codeLine = /\.(?:cs|rs|[cm]?[jt]sx?|py)$/.test(lowerFile)
      ? getMaskedLine(currentFile, currentLine, added)
      : added;
    diffEvents.push({ file: currentFile, line: currentLine, kind: "add", raw: added, code: codeLine });

    const pushCheat = (idSuffix: string, rule: string, message: string, fix: string): void => {
      findings.push({ id: `DIFF:${idSuffix}:${currentFile}:${currentLine}`, rule, category: "cheat", rung: "R0", severity: "error", file: currentFile, line: currentLine, message, fix });
    };

    if (isWorkflowOrScript && /git\s+(?:push|commit)\b[^#\n]*--no-verify|\bHUSKY=0\b/.test(stripped)) {
      pushCheat("no-verify", "diff-hook-bypass", "Added hook bypass (--no-verify or HUSKY=0) in diff.", "Remove the hook bypass and make the pre-push/pre-commit check pass cleanly.");
    }
    if (isWorkflowOrScript && /\|\|\s*(?:true\b|:)/.test(stripped) && CHECK_TOOL.test(stripped)) {
      pushCheat("swallowed", "diff-swallowed-failure", "Added '|| true' after a check command in diff.", "Remove '|| true' and fix the failing check.");
    }
    if (/\[(?:Fact|Theory|Test|TestMethod)\s*\([^\]]*\bSkip\s*=|\[Ignore\b/.test(codeLine) && lowerFile.endsWith(".cs")) {
      pushCheat("cs-skip", "diff-csharp-skipped-test", "Added skipped/ignored C# test attribute in diff.", "Fix or delete the test instead of skipping it with Skip= or [Ignore].");
    }
    if (/<TreatWarningsAsErrors>\s*false\s*<\/TreatWarningsAsErrors>/i.test(added) && /(?:\.csproj|Directory\.Build\.props)$/i.test(currentFile)) {
      pushCheat("cs-warn-false", "diff-csproj-warnings-not-errors", "Disabled TreatWarningsAsErrors in MSBuild config diff.", "Keep <TreatWarningsAsErrors>true</TreatWarningsAsErrors> enabled.");
    }
    if (/<NoWarn>\s*[^<\s][^<]*<\/NoWarn>/i.test(added) && /(?:\.csproj|Directory\.Build\.props)$/i.test(currentFile)) {
      pushCheat("cs-nowarn", "diff-csproj-nowarn", "Added <NoWarn> suppression in MSBuild config diff.", "Fix the warning at the source instead of adding global <NoWarn> entries.");
    }
    if (/^\s*#pragma\s+warning\s+disable\b/.test(codeLine) && !/(?:\/\/\s*(?:WARNING|SAFETY):|--\s*\S)/i.test(added) && lowerFile.endsWith(".cs")) {
      pushCheat("cs-pragma", "diff-csharp-pragma-disable", "Added unjustified #pragma warning disable in diff.", "Fix the warning or document a concrete // WARNING: or // SAFETY: reason.");
    }
    if (/^\s*#\[ignore\b/.test(codeLine) && lowerFile.endsWith(".rs")) {
      pushCheat("rs-ignore", "diff-rust-ignored-test", "Added #[ignore] on a Rust test in diff.", "Fix or delete the test instead of ignoring it.");
    }
    if (/#!?\s*\[\s*allow\s*\([^)]*(?:warnings|clippy::all|clippy::unwrap_used|clippy::wildcard_enum_match_arm)/i.test(codeLine) && !/reason\s*=/.test(added) && lowerFile.endsWith(".rs")) {
      pushCheat("rs-allow", "diff-rust-allow-lint", "Added blanket #[allow(...)] lint suppression in Rust diff.", 'Fix the warning or use #[expect(..., reason = "<invariant>")].');
    }
    if (/@(?:pytest\.mark\.(?:skip|xfail)|unittest\.skip)\b/.test(codeLine) && lowerFile.endsWith(".py")) {
      pushCheat("py-skip", "diff-python-skipped-test", "Added @pytest.mark.skip / xfail / @unittest.skip in Python diff.", "Fix or delete the test instead of skipping it.");
    }
    if (/#\s*(?:type:\s*ignore\s*$|noqa\s*$)/.test(added) && lowerFile.endsWith(".py")) {
      pushCheat("py-suppress", "diff-python-bare-suppression", "Added bare '# type: ignore' or '# noqa' suppression in Python diff.", "Fix the diagnostic or attach an explicit error code and concrete reason.");
    }
    if (isTestFilePath(currentFile) && /\b(?:describe|test|it)(?:\.concurrent)?\.(?:skip|only|todo|fixme)\s*\(|\b(?:xdescribe|xit|xtest|fdescribe|fit)\s*\(/.test(codeLine) && /\.[cm]?[jt]sx?$/.test(lowerFile)) {
      pushCheat("ts-skip", "diff-ts-skipped-test", "Added skipped/focused TS/JS test (.skip/.only/.todo) in diff.", "Fix or delete the test instead of skipping or focusing it.");
    }
    if (/\bgc\.disable\s*\(\s*\)|#\s*pragma\s+GCC\s+optimize\b|\bGC\.TryStartNoGCRegion\s*\(/.test(codeLine)) {
      pushCheat("perf-cheat", "diff-perf-benchmark-tampering", "Added GC-disabling or compiler-pragma benchmark tampering in diff.", "Remove benchmark tampering and optimize the actual algorithm or data layout.");
    }
    if ((/\bgit\s+(?:log\s+--all|show\s+origin\/|rev-list\s+--all)\b/.test(added) && /test|spec/i.test(lowerFile)) || /\bprocess\.env\.NODE_ENV\s*===?\s*["']test["']\s*&&\s*[A-Za-z0-9_.]+\s*===?\s*["']/.test(added)) {
      pushCheat("agent-cheat", "diff-agent-oracle-tampering", "Added agent reward-hacking pattern (test-specific input hardcoding in prod or git history mining in tests).", "Implement the genuine general fix without branching on test inputs or inspecting git history.");
    }

    if (isWorkflowOrScript) {
      for (const rule of WORKFLOW_CHEATS) {
        if (!rule.regex.test(stripped)) continue;
        if (rule.rule === "ci-pipe-tail-head" && !CHECK_TOOL.test(stripped)) continue;
        findings.push({
          id: `DIFF:${rule.rule}:${currentFile}:${currentLine}`,
          rule: rule.rule,
          category: "cheat",
          rung: "R0",
          severity: rule.severity,
          file: currentFile,
          line: currentLine,
          message: `Added in diff: ${rule.message}`,
          fix: rule.fix,
        });
      }
    }

    currentLine += 1;
  }

  const { events: normalizedEvents, migratedJsToTsFiles } = normalizeDiffMigrationPairs(diffEvents);
  for (const f of renamedJsToTsFiles) migratedJsToTsFiles.add(f);
  for (const delFile of deletedFiles) {
    const jsMatch = /^(.+)\.([cm]?)js(x?)$/i.exec(delFile);
    const migratedTarget = jsMatch ? `${jsMatch[1]}.${jsMatch[2]}ts${jsMatch[3]}` : "";
    if (migratedTarget && migratedJsToTsFiles.has(migratedTarget)) continue;
    if (isTestFilePath(delFile)) {
      findings.push({
        id: `DIFF:test-file-deleted:${delFile}`,
        rule: "diff-test-file-deleted",
        category: "cheat",
        rung: "R0",
        severity: "error",
        file: delFile,
        line: 1,
        message: `Entire test file '${delFile}' was deleted in diff.`,
        fix: "Restore or replace deleted test coverage instead of deleting test files to silence failures.",
      });
    } else if (/^\.github\/workflows\/.+\.ya?ml$/i.test(delFile)) {
      findings.push({
        id: `DIFF:workflow-deleted:${delFile}`,
        rule: "diff-ci-safety-gate-removed",
        category: "cheat",
        rung: "R0",
        severity: "error",
        file: delFile,
        line: 1,
        message: `CI workflow file '${delFile}' was deleted in diff.`,
        fix: "Restore the CI workflow file so PR-blocking verification gates stay active.",
      });
    }
  }
  findings.push(...auditDiffAntiEvasion(normalizedEvents, { migratedJsToTsFiles }));
  findings.push(...auditDiffInvariantLoss(normalizedEvents, { allowTestedPredicateRefactor: true, migratedJsToTsFiles }));
  findings.push(...auditManifestDowngrade(repoPath, baseRef));
  findings.push(...scanUntrackedConfigCheats(repoPath));

  return findings;
}
