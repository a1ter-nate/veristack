import type { Finding } from "../types.ts";

export interface DiffLineEvent {
  file: string;
  line: number;
  kind: "add" | "del";
  raw: string;
  code: string;
}

const STRICT_CONFIG_PATH = /(?:^|\/)(?:tsconfig(?:\.[^/]+)?\.json|\.?oxlintrc\.jsonc?|oxlint\.config\.ts|biome\.jsonc?|\.?ruff\.toml|pyproject\.toml|mypy\.ini|pyrightconfig\.json|\.?clippy\.toml|\.?golangci\.ya?ml|\.vstackignore|\.eslintignore|(?:\.verification\/)?\.?vstack\.json|\.verification\/invariants\.json)$/i;
const TEST_FILE_PATH = /(?:\.(?:test|spec)\.[cm]?[jt]sx?$|_test\.go$|_tests?\.rs$|(?:^|\/)test_[^/]+\.py$|tests?\.cs$)/i;
const ASSERT_CALL = /\b(?:assert|expect|Assert\.|assert_eq!|assert_ne!|assert!|require\.|should\.)/;
const GATE_TOOL_LINE = /\b(?:vstack|fail-on-cheats|fail-on-errors|clippy|mypy|pyright|tsgo|oxlint|ruff|TreatWarningsAsErrors|red-before-fix)\b/;

function pushDiff(
  findings: Finding[],
  file: string,
  line: number,
  rule: string,
  message: string,
  fix: string,
): void {
  findings.push({
    id: `DIFF:${rule}:${file}:${line}`,
    rule,
    category: "cheat",
    rung: "R0",
    severity: "error",
    file,
    line,
    message,
    fix,
  });
}

export function auditDiffAntiEvasion(events: readonly DiffLineEvent[]): Finding[] {
  const findings: Finding[] = [];
  const testAddedAsserts = new Map<string, number>();
  const testDeletedAsserts = new Map<string, { count: number; firstLine: number }>();

  for (const ev of events) {
    const lower = ev.file.toLowerCase();

    if (ev.kind === "add") {
      if (/\.[cm]?[jt]sx?$/.test(lower)) {
        if (/\/\/\s*@ts-(?:ignore|nocheck)\b|\/\*\s*@ts-(?:ignore|nocheck)\b/.test(ev.raw)) {
          pushDiff(
            findings, ev.file, ev.line, "diff-ts-suppression-added",
            "Added @ts-ignore/@ts-nocheck type-safety escape hatch in diff.",
            "Fix the underlying type error instead of disabling the TypeScript compiler.",
          );
        } else if (/\/\/\s*@ts-expect-error\s*$/.test(ev.raw)) {
          pushDiff(
            findings, ev.file, ev.line, "diff-ts-suppression-added",
            "Added bare @ts-expect-error without a concrete justification in diff.",
            "Fix the type mismatch or document the exact invariant after @ts-expect-error.",
          );
        } else if (/(?:eslint|oxlint)-disable(?:-next-line|-line)?\s*(?:\*\/|$)|biome-ignore\s+[a-z0-9/]+\s*:?\s*(?:\*\/|$)/i.test(ev.raw)) {
          pushDiff(
            findings, ev.file, ev.line, "diff-ts-suppression-added",
            "Added blanket linter suppression (eslint-disable/oxlint-disable/biome-ignore) without reason in diff.",
            "Fix the lint finding instead of suppressing the linter.",
          );
        }
      }

      if (lower.endsWith(".go") && /\/\/\s*nolint(?:\s*$|\s*:[a-z0-9,-]+\s*$)/i.test(ev.raw)) {
        pushDiff(
          findings, ev.file, ev.line, "diff-go-nolint-added",
          "Added unjustified //nolint directive in Go diff.",
          "Fix the linter issue or scope //nolint:<linter> with a concrete // justification.",
        );
      }

      if (STRICT_CONFIG_PATH.test(ev.file)) {
        if (/"(?:strict|strictNullChecks|noImplicitAny|exactOptionalPropertyTypes)"\s*:\s*false/.test(ev.raw)) {
          pushDiff(
            findings, ev.file, ev.line, "diff-config-strictness-downgrade",
            "Downgraded TypeScript strictness flag to false in config diff.",
            "Keep TypeScript strict compiler flags enabled and fix the offending code.",
          );
        }
        if (lower.endsWith(".vstackignore") && ev.raw.trim().length > 0 && !ev.raw.trim().startsWith("#")) {
          pushDiff(
            findings, ev.file, ev.line, "diff-config-strictness-downgrade",
            `Added new path exclusion ('${ev.raw.trim()}') to .vstackignore in diff.`,
            "Fix findings directly instead of excluding paths from verification.",
          );
        }
        if (/(?:oxlint|biome|ruff|mypy|clippy|golangci|vstack\.json)/i.test(lower) && /(?:"off"|\bdisallow_untyped_defs\s*=\s*false|\bstrict\s*=\s*false|\bignore\s*=\s*\[|"disabledRules"\s*:)/i.test(ev.raw)) {
          pushDiff(
            findings, ev.file, ev.line, "diff-config-strictness-downgrade",
            "Relaxed linter/typechecker strictness rule in config diff.",
            "Keep strict lint/type rules enforced rather than disabling them in config.",
          );
        }
      }

      if (TEST_FILE_PATH.test(ev.file) && ASSERT_CALL.test(ev.code)) {
        testAddedAsserts.set(ev.file, (testAddedAsserts.get(ev.file) ?? 0) + 1);
      }
    } else {
      if (TEST_FILE_PATH.test(ev.file) && ASSERT_CALL.test(ev.raw)) {
        const cur = testDeletedAsserts.get(ev.file) ?? { count: 0, firstLine: ev.line };
        cur.count += 1;
        testDeletedAsserts.set(ev.file, cur);
      }

      const isCiOrHook = /(?:^|\/)(?:\.github\/workflows\/|lefthook\.yml|\.husky\/|package\.json)/i.test(ev.file);
      if (/\.verification\/invariants\.json$/i.test(ev.file) && /"kind"\s*:/.test(ev.raw)) {
        pushDiff(
          findings, ev.file, ev.line, "diff-config-strictness-downgrade",
          "Deleted dynamic invariant entry from .verification/invariants.json in diff.",
          "Keep locked dynamic invariants intact; update .verification/invariants.json only via human-reviewed baseline changes.",
        );
      }
      if (isCiOrHook && GATE_TOOL_LINE.test(ev.raw) && !ev.raw.trim().startsWith("#")) {
        const hasMatchingAdd = events.some(
          (other) => other.kind === "add" && other.file === ev.file && GATE_TOOL_LINE.test(other.raw),
        );
        if (!hasMatchingAdd) {
          pushDiff(
            findings, ev.file, ev.line, "diff-ci-safety-gate-removed",
            "Removed verification/linter gate from CI workflow or hook without replacement.",
            "Keep verification gates active in CI and hooks; fix underlying failures instead of removing checks.",
          );
        }
      }
    }
  }

  for (const [file, delInfo] of testDeletedAsserts.entries()) {
    const addedCount = testAddedAsserts.get(file) ?? 0;
    if (delInfo.count >= 2 && addedCount === 0) {
      pushDiff(
        findings, file, delInfo.firstLine, "diff-assertion-deleted",
        `Deleted ${delInfo.count} test assertion(s) in ${file} without adding any replacement assertions.`,
        "Preserve or strengthen test assertions; never delete assertions to make a failing test pass.",
      );
    }
  }

  return findings;
}
