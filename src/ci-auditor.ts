import { spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import type { DiscoveredRepo } from "./discover.ts";
import { auditDiffInvariantLoss } from "./ast/invariant-loss.ts";
import { maskStrings } from "./test-lexical.ts";
import type { Finding } from "./types.ts";
import { auditDiffAntiEvasion, type DiffLineEvent } from "./zero-defect/anti-evasion.ts";
import { auditExtendedCiRules, auditMaestroFlow } from "./zero-defect/ci-workflow-rules.ts";

const CHECK_TOOL =
  /\b(?:pnpm|npm|yarn|npx|bun|pytest|vitest|jest|tsc|tsgo|eslint|oxlint|prettier|ruff|mypy|cargo|go|make|gradle|mvn|dotnet|unittest|vstack)\b/i;

const WORKFLOW_CHEATS: ReadonlyArray<{
  rule: string;
  regex: RegExp;
  severity: Finding["severity"];
  message: string;
  fix: string;
}> = [
  {
    rule: "ci-continue-on-error",
    regex: /continue-on-error:\s*true/i,
    severity: "error",
    message: "Workflow sets continue-on-error: true, silently hiding failures.",
    fix: "Remove continue-on-error: true so failing checks block merges.",
  },
  {
    rule: "ci-pull-request-target",
    regex: /\bpull_request_target\b/,
    severity: "error",
    message: "pull_request_target exposes repository secrets/write access to untrusted PRs.",
    fix: "Use pull_request trigger with minimal read-only permissions.",
  },
  {
    rule: "ci-wide-permissions",
    regex: /permissions:\s*write-all|\bcontents:\s*write\b/,
    severity: "error",
    message: "Workflow grants overly wide write permissions.",
    fix: "Restrict permissions to contents: read and grant narrow scopes only to release jobs.",
  },
  {
    rule: "ci-retry-action",
    regex: /\bnick-fields\/retry\b|\b--reruns\b|\bretry-attempts\b/i,
    severity: "error",
    message: "CI step retries failed commands, masking flaky tests.",
    fix: "Remove CI retries and fix the underlying flake deterministically.",
  },
  {
    rule: "ci-excessive-timeout",
    regex: /timeout-minutes:\s*\d{3,}/,
    severity: "warn",
    message: "Workflow timeout >= 100 minutes hides hangs and burns runner budget.",
    fix: "Lower timeout-minutes to match the actual critical path (typically 5–20m).",
  },
  {
    rule: "ci-pipe-tail-head",
    regex: /\|\s*(?:tail|head)\b/,
    severity: "error",
    message: "Piping a check command into tail/head masks non-zero exit codes without pipefail.",
    fix: "Write command output to a log file and read the file instead of piping.",
  },
];

export function auditCiWorkflows(repo: DiscoveredRepo): Finding[] {
  const findings: Finding[] = [];

  for (const file of repo.files) {
    if (!file.isWorkflow) {
      findings.push(...auditMaestroFlow(file));
      continue;
    }
    const lines = file.content.split(/\r?\n/);

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
  const diff = spawnSync("git", ["-C", repoPath, "diff", baseRef, "--unified=0", "--no-color"], {
    encoding: "utf8",
  });
  if (diff.status !== 0) return [];

  const findings: Finding[] = [];
  const diffEvents: DiffLineEvent[] = [];
  let currentFile = "<diff>";
  let currentLine = 1;

  const maskedCache = new Map<string, string[] | null>();
  const getMaskedLine = (rel: string, lineNum: number, fallback: string): string => {
    let lines = maskedCache.get(rel);
    if (lines === undefined) {
      const fullPath = path.resolve(repoPath, rel);
      try {
        const rawText = fs.readFileSync(fullPath, "utf8");
        lines = maskStrings(rawText).split(/\r?\n/);
      } catch {
        lines = null;
      }
      maskedCache.set(rel, lines);
    }
    if (!lines) return fallback;
    return lines[lineNum - 1] ?? fallback;
  };

  for (const raw of diff.stdout.split(/\r?\n/)) {
    if (raw.startsWith("+++ b/")) {
      currentFile = raw.slice(6);
      continue;
    }
    const hunk = /^@@ -\d+(?:,\d+)? \+(\d+)/.exec(raw);
    if (hunk) {
      currentLine = Number(hunk[1]);
      continue;
    }
    if (raw.startsWith("-") && !raw.startsWith("---")) {
      const removed = raw.slice(1);
      if (!/\.(?:md|mdx|txt|rst)$/.test(currentFile.toLowerCase())) {
        diffEvents.push({ file: currentFile, line: currentLine, kind: "del", raw: removed, code: removed });
      }
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

    if (isWorkflowOrScript && /git\s+(?:push|commit)\b[^#\n]*--no-verify|\bHUSKY=0\b/.test(stripped)) {
      findings.push({
        id: `DIFF:no-verify:${currentFile}:${currentLine}`,
        rule: "diff-hook-bypass",
        category: "cheat",
        rung: "R0",
        severity: "error",
        file: currentFile,
        line: currentLine,
        message: "Added hook bypass (--no-verify or HUSKY=0) in diff.",
        fix: "Remove the hook bypass and make the pre-push/pre-commit check pass cleanly.",
      });
    }

    if (isWorkflowOrScript && /\|\|\s*(?:true\b|:)/.test(stripped) && CHECK_TOOL.test(stripped)) {
      findings.push({
        id: `DIFF:swallowed:${currentFile}:${currentLine}`,
        rule: "diff-swallowed-failure",
        category: "cheat",
        rung: "R0",
        severity: "error",
        file: currentFile,
        line: currentLine,
        message: "Added '|| true' after a check command in diff.",
        fix: "Remove '|| true' and fix the failing check.",
      });
    }

    if (
      /\[(?:Fact|Theory|Test|TestMethod)\s*\([^\]]*\bSkip\s*=|\[Ignore\b/.test(codeLine) &&
      lowerFile.endsWith(".cs")
    ) {
      findings.push({
        id: `DIFF:cs-skip:${currentFile}:${currentLine}`,
        rule: "diff-csharp-skipped-test",
        category: "cheat",
        rung: "R0",
        severity: "error",
        file: currentFile,
        line: currentLine,
        message: "Added skipped/ignored C# test attribute in diff.",
        fix: "Fix or delete the test instead of skipping it with Skip= or [Ignore].",
      });
    }

    if (
      /<TreatWarningsAsErrors>\s*false\s*<\/TreatWarningsAsErrors>/i.test(added) &&
      /(?:\.csproj|Directory\.Build\.props)$/i.test(currentFile)
    ) {
      findings.push({
        id: `DIFF:cs-warn-false:${currentFile}:${currentLine}`,
        rule: "diff-csproj-warnings-not-errors",
        category: "cheat",
        rung: "R0",
        severity: "error",
        file: currentFile,
        line: currentLine,
        message: "Disabled TreatWarningsAsErrors in MSBuild config diff.",
        fix: "Keep <TreatWarningsAsErrors>true</TreatWarningsAsErrors> enabled.",
      });
    }

    if (
      /<NoWarn>\s*[^<\s][^<]*<\/NoWarn>/i.test(added) &&
      /(?:\.csproj|Directory\.Build\.props)$/i.test(currentFile)
    ) {
      findings.push({
        id: `DIFF:cs-nowarn:${currentFile}:${currentLine}`,
        rule: "diff-csproj-nowarn",
        category: "cheat",
        rung: "R0",
        severity: "error",
        file: currentFile,
        line: currentLine,
        message: "Added <NoWarn> suppression in MSBuild config diff.",
        fix: "Fix the warning at the source instead of adding global <NoWarn> entries.",
      });
    }

    if (
      /^\s*#pragma\s+warning\s+disable\b/.test(codeLine) &&
      !/(?:\/\/\s*(?:WARNING|SAFETY):|--\s*\S)/i.test(added) &&
      lowerFile.endsWith(".cs")
    ) {
      findings.push({
        id: `DIFF:cs-pragma:${currentFile}:${currentLine}`,
        rule: "diff-csharp-pragma-disable",
        category: "cheat",
        rung: "R0",
        severity: "error",
        file: currentFile,
        line: currentLine,
        message: "Added unjustified #pragma warning disable in diff.",
        fix: "Fix the warning or document a concrete // WARNING: or // SAFETY: reason.",
      });
    }

    if (/^\s*#\[ignore\b/.test(codeLine) && lowerFile.endsWith(".rs")) {
      findings.push({
        id: `DIFF:rs-ignore:${currentFile}:${currentLine}`,
        rule: "diff-rust-ignored-test",
        category: "cheat",
        rung: "R0",
        severity: "error",
        file: currentFile,
        line: currentLine,
        message: "Added #[ignore] on a Rust test in diff.",
        fix: "Fix or delete the test instead of ignoring it.",
      });
    }

    if (
      /#!?\s*\[\s*allow\s*\([^)]*(?:warnings|clippy::all|clippy::unwrap_used|clippy::wildcard_enum_match_arm)/i.test(
        codeLine,
      ) &&
      !/reason\s*=/.test(added) &&
      lowerFile.endsWith(".rs")
    ) {
      findings.push({
        id: `DIFF:rs-allow:${currentFile}:${currentLine}`,
        rule: "diff-rust-allow-lint",
        category: "cheat",
        rung: "R0",
        severity: "error",
        file: currentFile,
        line: currentLine,
        message: "Added blanket #[allow(...)] lint suppression in Rust diff.",
        fix: 'Fix the warning or use #[expect(..., reason = "<invariant>")].',
      });
    }

    if (/@(?:pytest\.mark\.(?:skip|xfail)|unittest\.skip)\b/.test(codeLine) && lowerFile.endsWith(".py")) {
      findings.push({
        id: `DIFF:py-skip:${currentFile}:${currentLine}`,
        rule: "diff-python-skipped-test",
        category: "cheat",
        rung: "R0",
        severity: "error",
        file: currentFile,
        line: currentLine,
        message: "Added @pytest.mark.skip / xfail / @unittest.skip in Python diff.",
        fix: "Fix or delete the test instead of skipping it.",
      });
    }

    if (/#\s*(?:type:\s*ignore\s*$|noqa\s*$)/.test(added) && lowerFile.endsWith(".py")) {
      findings.push({
        id: `DIFF:py-suppress:${currentFile}:${currentLine}`,
        rule: "diff-python-bare-suppression",
        category: "cheat",
        rung: "R0",
        severity: "error",
        file: currentFile,
        line: currentLine,
        message: "Added bare '# type: ignore' or '# noqa' suppression in Python diff.",
        fix: "Fix the diagnostic or attach an explicit error code and concrete reason.",
      });
    }

    if (
      /\b(?:describe|test|it)(?:\.concurrent)?\.(?:skip|only|todo|fixme)\s*\(|\b(?:xdescribe|xit|xtest|fdescribe|fit)\s*\(/.test(
        codeLine,
      ) &&
      /\.[cm]?[jt]sx?$/.test(lowerFile)
    ) {
      findings.push({
        id: `DIFF:ts-skip:${currentFile}:${currentLine}`,
        rule: "diff-ts-skipped-test",
        category: "cheat",
        rung: "R0",
        severity: "error",
        file: currentFile,
        line: currentLine,
        message: "Added skipped/focused TS/JS test (.skip/.only/.todo) in diff.",
        fix: "Fix or delete the test instead of skipping or focusing it.",
      });
    }

    if (/\bgc\.disable\s*\(\s*\)|#\s*pragma\s+GCC\s+optimize\b|\bGC\.TryStartNoGCRegion\s*\(/.test(codeLine)) {
      findings.push({
        id: `DIFF:perf-cheat:${currentFile}:${currentLine}`,
        rule: "diff-perf-benchmark-tampering",
        category: "cheat",
        rung: "R0",
        severity: "error",
        file: currentFile,
        line: currentLine,
        message: "Added GC-disabling or compiler-pragma benchmark tampering in diff.",
        fix: "Remove benchmark tampering and optimize the actual algorithm or data layout.",
      });
    }

    if (
      (/\bgit\s+(?:log\s+--all|show\s+origin\/|rev-list\s+--all)\b/.test(added) && /test|spec/i.test(lowerFile)) ||
      /\bprocess\.env\.NODE_ENV\s*===?\s*["']test["']\s*&&\s*[A-Za-z0-9_.]+\s*===?\s*["']/.test(added)
    ) {
      findings.push({
        id: `DIFF:agent-cheat:${currentFile}:${currentLine}`,
        rule: "diff-agent-oracle-tampering",
        category: "cheat",
        rung: "R0",
        severity: "error",
        file: currentFile,
        line: currentLine,
        message: "Added agent reward-hacking pattern (test-specific input hardcoding in prod or git history mining in tests).",
        fix: "Implement the genuine general fix without branching on test inputs or inspecting git history.",
      });
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

  findings.push(...auditDiffAntiEvasion(diffEvents));
  findings.push(...auditDiffInvariantLoss(diffEvents));

  return findings;
}
