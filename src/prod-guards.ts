import { analyzeLinearObligations } from "./ast/linear-obligations.ts";
import { analyzeTsAstGuards, parseTsAst } from "./ast/ts-ast.ts";
import { analyzeWave5AiFirstGuards } from "./ast/wave5-ai-first.ts";
import { analyzeWave6TitansAGuards } from "./ast/wave6-titans-a.ts";
import { analyzeWave7TitansBGuards } from "./ast/wave7-titans-b.ts";
import type { DiscoveredRepo } from "./discover.ts";
import { lineOf, maskCode } from "./test-lexical.ts";
import type { Finding } from "./types.ts";
import { analyzeCveAndPostmortemGuards } from "./zero-defect/cve-and-agent-guards.ts";
import { analyzeEcosystemGuards } from "./zero-defect/ecosystem-guards.ts";
import { analyzeOssGuards } from "./zero-defect/oss-guards.ts";
import { analyzeRuntimeGuards } from "./zero-defect/runtime-guards.ts";

const GENERATED_PATH = /(?:^|\/)(?:generated|generated-clients?|codegen|__snapshots__)\/|\.(?:gen|generated)\.[cm]?[jt]sx?$/i;

const PY_TEST_ONLY_EXPORT = /\bdef\s+[a-zA-Z0-9_]*(?:_for_testing|_test_only)\s*\(/g;
const PY_ANY_ESCAPE = /\bcast\s*\(\s*Any\b|:\s*Any\b|->\s*Any\b/g;
const PY_SWALLOWING_EXCEPT = /^\s*except(?:\s+[A-Za-z_][A-Za-z0-9_.]*(?:\s+as\s+[A-Za-z_][A-Za-z0-9_]*)?)?\s*:\s*\r?\n\s*pass\b/gm;
const PY_BARE_SUPPRESSION = /#\s*(?:type:\s*ignore\s*(?:$|\r?\n)|noqa\s*(?:$|\r?\n))/gm;
const PY_PROD_ASSERT = /^\s*assert\s+(?!_?never\b)/gm;

const CSHARP_DEBUG_ASSERT = /\bDebug\.Assert\s*\(/g;
const RUST_DEBUG_ASSERT = /\bdebug_assert(?:_eq|_ne)?!\s*\(/g;

const CDC_WALL_CLOCK_TS = /\bDate\.now\s*\(\s*\)\s*-\s*[A-Za-z_$][A-Za-z0-9_$.]*/g;
const CDC_WALL_CLOCK_CS = /\bDateTime(?:Offset)?\.(?:Utc)?Now\s*-\s*[A-Za-z_][A-Za-z0-9_.]*/g;
const CDC_WALL_CLOCK_RS = /\bSystemTime::now\s*\(\s*\)\s*\.duration_since\b|\b(?:Utc|Local)::now\s*\(\s*\)\s*-\s*[A-Za-z_]/g;
const CDC_WALL_CLOCK_PY = /\b(?:datetime\.(?:utc)?now\s*\([^)]*\)|time\.time\s*\(\s*\))\s*-\s*[A-Za-z_][A-Za-z0-9_.]*/g;

const UNBOUNDED_LOOP = /\bwhile\s*\(\s*true\s*\)|\bwhile\s+True\s*:|\bloop\s*\{/g;

export function analyzeProdZeroDefectRules(repo: DiscoveredRepo): Finding[] {
  const findings: Finding[] = [];

  for (const file of repo.files) {
    if (file.rel.endsWith(".sql")) {
      if (/(?:^|\/)migrations?\//i.test(file.rel)) {
        findings.push(...analyzeCveAndPostmortemGuards(file));
      }
      findings.push(...analyzeWave6TitansAGuards(file));
      findings.push(...analyzeWave7TitansBGuards(file));
      continue;
    }
    if (/\.(?:sh|bash)$/i.test(file.rel)) {
      findings.push(...analyzeWave5AiFirstGuards(file));
      findings.push(...analyzeWave7TitansBGuards(file));
      continue;
    }
    if (!file.language || file.isTest || GENERATED_PATH.test(file.rel)) continue;
    const raw = file.content;
    const maskedAll = maskCode(raw, file.language);
    const cfgTestIdx = file.language === "rust" ? raw.search(/#\[cfg\(test\)\]/) : -1;
    const masked = cfgTestIdx >= 0 ? maskedAll.slice(0, cfgTestIdx) : maskedAll;

    if (file.language === "python") {
      for (const match of masked.matchAll(PY_TEST_ONLY_EXPORT)) {
        const line = lineOf(raw, match.index ?? 0);
        findings.push({
          id: `ST:py-test-seam:${file.rel}:${line}`,
          rule: "no-test-only-production-seam",
          category: "structure",
          rung: "R1",
          severity: "warn",
          file: file.rel,
          line,
          message: `Test-only function in Python production module: ${match[0].trim()}.`,
          fix: "Remove test-only production backdoors and verify behavior through the public API.",
        });
      }

      for (const match of masked.matchAll(PY_ANY_ESCAPE)) {
        const line = lineOf(raw, match.index ?? 0);
        findings.push({
          id: `AS:py-any:${file.rel}:${line}`,
          rule: "no-chained-or-any-cast",
          category: "structure",
          rung: "R0",
          severity: "error",
          file: file.rel,
          line,
          message: `Python Any type escape hatch (${match[0].trim()}) disables static type safety.`,
          fix: "Use object, Protocol, TypeVar, or a validated dataclass/Pydantic model at the boundary.",
        });
      }

      for (const match of masked.matchAll(PY_SWALLOWING_EXCEPT)) {
        const line = lineOf(raw, match.index ?? 0);
        findings.push({
          id: `ST:py-swallow:${file.rel}:${line}`,
          rule: "no-swallowing-catch",
          category: "structure",
          rung: "R0",
          severity: "error",
          file: file.rel,
          line,
          message: "Python except-pass block silently swallows errors.",
          fix: "Rethrow, return a typed failure variant, or handle the specific expected exception explicitly.",
        });
      }

      for (const match of raw.matchAll(PY_BARE_SUPPRESSION)) {
        const line = lineOf(raw, match.index ?? 0);
        findings.push({
          id: `SU:py-bare:${file.rel}:${line}`,
          rule: "suppression-audit",
          category: "structure",
          rung: "R0",
          severity: "error",
          file: file.rel,
          line,
          message: "Bare '# type: ignore' or '# noqa' without an error code and concrete reason.",
          fix: "Fix the diagnostic or scope to a specific code with an inline reason.",
        });
      }

      for (const match of masked.matchAll(PY_PROD_ASSERT)) {
        const line = lineOf(raw, match.index ?? 0);
        findings.push({
          id: `ZD:py-assert:${file.rel}:${line}`,
          rule: "no-release-stripped-assert",
          category: "structure",
          rung: "R1",
          severity: "warn",
          file: file.rel,
          line,
          message: "Python bare 'assert' in production code is stripped under 'python -O' (violates Runtime Jidoka V36).",
          fix: "Raise an explicit InvariantViolationError (e.g., if not cond: raise InvariantViolationError(...)) so invariants stay active in release.",
        });
      }
    }

    if (file.language === "csharp") {
      for (const match of masked.matchAll(CSHARP_DEBUG_ASSERT)) {
        const line = lineOf(raw, match.index ?? 0);
        findings.push({
          id: `ZD:cs-debug-assert:${file.rel}:${line}`,
          rule: "no-release-stripped-assert",
          category: "structure",
          rung: "R1",
          severity: "warn",
          file: file.rel,
          line,
          message: "Debug.Assert compiles out in Release builds (violates Runtime Jidoka V36).",
          fix: "Use an always-on production invariant guard (e.g., Invariant.Require / InvalidOperationException).",
        });
      }
    }

    if (file.language === "rust") {
      for (const match of masked.matchAll(RUST_DEBUG_ASSERT)) {
        const line = lineOf(raw, match.index ?? 0);
        findings.push({
          id: `ZD:rs-debug-assert:${file.rel}:${line}`,
          rule: "no-release-stripped-assert",
          category: "structure",
          rung: "R1",
          severity: "warn",
          file: file.rel,
          line,
          message: "debug_assert! is stripped in --release builds (violates Runtime Jidoka V36 for corruption-critical invariants).",
          fix: "Use release-active assert! or return a typed invariant error variant.",
        });
      }
    }

    const cdcRegex =
      file.language === "typescript" || file.language === "javascript"
        ? CDC_WALL_CLOCK_TS
        : file.language === "csharp"
          ? CDC_WALL_CLOCK_CS
          : file.language === "rust"
            ? CDC_WALL_CLOCK_RS
            : file.language === "python"
              ? CDC_WALL_CLOCK_PY
              : undefined;

    if (cdcRegex) {
      for (const match of masked.matchAll(cdcRegex)) {
        const line = lineOf(raw, match.index ?? 0);
        findings.push({
          id: `ZD:cdc-clock:${file.rel}:${line}`,
          rule: "cdc-wall-clock-duration",
          category: "structure",
          rung: "R1",
          severity: "warn",
          file: file.rel,
          line,
          message: `Wall-clock timestamp used for duration/elapsed math (${match[0].trim()}) breaks on NTP jumps or DST (V30 Clock CDC).`,
          fix: "Use a monotonic clock (performance.now / TimeProvider.GetTimestamp / std::time::Instant / time.monotonic).",
        });
      }
    }

    for (const match of masked.matchAll(UNBOUNDED_LOOP)) {
      const idx = match.index ?? 0;
      const window = masked.slice(Math.max(0, idx - 220), idx + 450);
      if (
        /\b(?:maxIter|max_iter|maxAttempts|max_attempts|maxRetries|max_retries|maxPages|max_pages|deadline|timeout|limit|fuel|budget|countdown)\b/i.test(
          window,
        )
      ) {
        continue;
      }
      const line = lineOf(raw, idx);
      findings.push({
        id: `ZD:unbounded-loop:${file.rel}:${line}`,
        rule: "unbounded-loop-risk",
        category: "structure",
        rung: "R1",
        severity: "warn",
        file: file.rel,
        line,
        message: `Unbounded loop (${match[0].trim()}) has no visible static iteration cap or fuel bound (V31 JPL Power of 10).`,
        fix: "Bound the loop with an explicit maxIterations/fuel ceiling or finite iterator.",
      });
    }

    findings.push(...analyzeRuntimeGuards(file));
    findings.push(...analyzeOssGuards(file));
    findings.push(...analyzeCveAndPostmortemGuards(file));
    findings.push(...analyzeWave5AiFirstGuards(file));
    findings.push(...analyzeWave6TitansAGuards(file));
    findings.push(...analyzeWave7TitansBGuards(file));
    const ast = parseTsAst(file);
    findings.push(...analyzeTsAstGuards(file, ast));
    findings.push(...analyzeLinearObligations(file, ast));
  }

  findings.push(...analyzeEcosystemGuards(repo));

  return findings;
}
