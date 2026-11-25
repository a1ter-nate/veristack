import path from "node:path";
import type { DiscoveredRepo } from "./discover.ts";
import { analyzeOracleAndInstructions } from "./oracle-audit.ts";
import { analyzeProdZeroDefectRules } from "./prod-guards.ts";
import { analyzeStateMachines } from "./state-machines/index.ts";
import { maskCode } from "./test-lexical.ts";
import type { Finding } from "./types.ts";
import { auditZeroDefectArtifacts } from "./zero-defect/index.ts";
import { analyzePerfHygiene } from "./zero-defect/perf-lints.ts";

const WIDE_DIR_LIMIT = 15;
const WARN_FILE_LINES = 500;
const HARD_FILE_LINES = 2000;
const MAX_EXPORTS = 6;
const MAX_AGENTS_LINES = 200;

const GENERATED_PATH = /(?:^|\/)(?:generated|generated-clients?|codegen|__snapshots__)\/|\.(?:gen|generated)\.[cm]?[jt]sx?$/i;
const TEST_ONLY_EXPORT =
  /\bexport\s+(?:async\s+)?(?:function|const|let|class|type)\s+[A-Za-z0-9_]*(?:ForTesting|TestOnly|__test|_testOnly|VisibleForTesting)\b/g;
const CHAINED_AS = /\bas\s+unknown\s+as\b|\bas\s+any\b/g;
const EXPORT_DECL = /^\s*export\s+(?:async\s+)?(?:function|const|let|class|enum)\s+[A-Za-z0-9_]+/gm;
const SWALLOWING_CATCH = /\bcatch\s*(?:\([^)]*\))?\s*\{\s*\}/g;
const CSHARP_TEST_ONLY_EXPORT =
  /\b(?:public|internal)\s+(?:static\s+)?(?:async\s+)?[A-Za-z0-9_<>,.\s?]+\s+[A-Za-z0-9_]*(?:ForTesting|TestOnly|VisibleForTesting)\b/g;
const CSHARP_DYNAMIC = /\bdynamic\s+[A-Za-z_][A-Za-z0-9_]*\b/g;
const CSHARP_PRAGMA_DISABLE = /^\s*#pragma\s+warning\s+disable\b([^\n]*)/gm;
const CSHARP_SUPPRESS_ATTR = /\[SuppressMessage\s*\(([^)\]]+)\)\]/g;
const CSPROJ_WARN_FALSE = /<TreatWarningsAsErrors>\s*false\s*<\/TreatWarningsAsErrors>/gi;
const CSPROJ_NOWARN = /<NoWarn>\s*([^<\s][^<]*)<\/NoWarn>/gi;
const RUST_NON_PROD_HARNESS = /(?:^|\/)(?:tests\/(?:support|helpers|fixtures|mocks|stubs)|fuzz|benches)\//i;
const RUST_TEST_ONLY_EXPORT = /\bpub(?:\([^)]*\))?\s+fn\s+[a-zA-Z0-9_]*(?:_for_testing|_test_only)\b/g;
const RUST_UNSAFE_OR_TRANSMUTE = /\bstd::mem::transmute\b|\bmem::transmute\b|\bunsafe\s*\{/g;
const RUST_SWALLOWING_ERR = /\bif\s+let\s+Err\s*\(\s*_\s*\)\s*=\s*[^\n{]+\{\s*\}|\bErr\s*\(\s*_\s*\)\s*=>\s*\{\s*\}/g;
const RUST_PROD_UNWRAP = /\.\s*(?:unwrap|expect)\s*\(/g;
const RUST_ALLOW_ATTR = /#!?\s*\[\s*allow\s*\(([^)]+)\)\s*\]/g;
const SUPPRESSION_DIRECTIVE =
  /(?:\/\/|\/\*)\s*(?:@ts-(?:ignore|nocheck)\b|(?:oxlint|eslint)-disable(?:-next-line|-line)?\s*(?:\*\/|$|\n)|(?:istanbul|c8|v8)\s+ignore\b)/g;

function lineOf(content: string, index: number): number {
  let line = 1;
  for (let i = 0; i < index; i++) {
    if (content[i] === "\n") line += 1;
  }
  return line;
}

export function analyzeStructure(repo: DiscoveredRepo): Finding[] {
  const findings: Finding[] = [];

  const dirMembers = new Map<string, Set<string>>();
  const dirSourceFiles = new Map<string, string[]>();

  for (const rel of repo.allRelPaths) {
    const dir = path.posix.dirname(rel);
    const base = path.posix.basename(rel);
    const members = dirMembers.get(dir) ?? new Set<string>();
    members.add(base);
    dirMembers.set(dir, members);
  }

  for (const file of repo.files) {
    const isGenerated = GENERATED_PATH.test(file.rel);

    if (file.language && !file.isTest && !isGenerated) {
      const dir = path.posix.dirname(file.rel);
      const list = dirSourceFiles.get(dir) ?? [];
      list.push(path.posix.basename(file.rel));
      dirSourceFiles.set(dir, list);
    }

    if (file.language && !file.isTest && !isGenerated && file.lines > WARN_FILE_LINES) {
      const isHard = file.lines > HARD_FILE_LINES;
      findings.push({
        id: `ST:long-file:${file.rel}`,
        rule: isHard ? "long-file" : "max-file-lines",
        category: "structure",
        rung: "R1",
        severity: isHard ? "error" : "warn",
        file: file.rel,
        line: 1,
        message: `${file.rel} has ${file.lines} lines (limit: ${isHard ? HARD_FILE_LINES : WARN_FILE_LINES}).`,
        fix: "Split cohesive responsibilities into deeper modules with narrow interfaces; avoid mechanical splits.",
      });
    }

    if ((file.language === "typescript" || file.language === "javascript") && !file.isTest && !isGenerated) {
      const codeOnly = maskCode(file.content, file.language);
      const exports = codeOnly.match(EXPORT_DECL);
      if (exports && exports.length > MAX_EXPORTS) {
        findings.push({
          id: `ST:max-exports:${file.rel}`,
          rule: "max-exports-per-module",
          category: "structure",
          rung: "R1",
          severity: "warn",
          file: file.rel,
          line: 1,
          message: `${file.rel} exports ${exports.length} declarations (budget: <= ${MAX_EXPORTS}).`,
          fix: "Hide internal helpers behind a narrower public interface (deep module) or move internals under internal/.",
        });
      }

      for (const match of codeOnly.matchAll(TEST_ONLY_EXPORT)) {
        const line = lineOf(file.content, match.index ?? 0);
        findings.push({
          id: `ST:test-seam:${file.rel}:${line}`,
          rule: "no-test-only-production-seam",
          category: "structure",
          rung: "R1",
          severity: "warn",
          file: file.rel,
          line,
          message: `Test-only export detected in production file: ${match[0].trim()}.`,
          fix: "Remove test-only production exports and verify behavior through the real public interface.",
        });
      }

      for (const match of codeOnly.matchAll(SWALLOWING_CATCH)) {
        const line = lineOf(file.content, match.index ?? 0);
        findings.push({
          id: `ST:swallow-catch:${file.rel}:${line}`,
          rule: "no-swallowing-catch",
          category: "structure",
          rung: "R0",
          severity: "warn",
          file: file.rel,
          line,
          message: "Empty catch block silently swallows errors.",
          fix: "Rethrow, return a typed failure result, or handle the specific expected error explicitly.",
        });
      }

      if (file.language === "typescript") {
        for (const match of codeOnly.matchAll(CHAINED_AS)) {
          const line = lineOf(file.content, match.index ?? 0);
          findings.push({
            id: `AS:cast:${file.rel}:${line}`,
            rule: "no-chained-or-any-cast",
            category: "structure",
            rung: "R0",
            severity: "error",
            file: file.rel,
            line,
            message: `Unsafe type escape hatch (${match[0]}) hides real contract.`,
            fix: "Parse external data once at the boundary with a schema or verifying type guard instead of casting.",
          });
        }
      }
    }

    if (file.language === "csharp" && !file.isTest && !isGenerated) {
      for (const match of file.content.matchAll(CSHARP_TEST_ONLY_EXPORT)) {
        const line = lineOf(file.content, match.index ?? 0);
        findings.push({
          id: `ST:cs-test-seam:${file.rel}:${line}`,
          rule: "no-test-only-production-seam",
          category: "structure",
          rung: "R1",
          severity: "warn",
          file: file.rel,
          line,
          message: `Test-only member detected in C# production file: ${match[0].trim()}.`,
          fix: "Remove test-only production backdoors and verify behavior through the public contract.",
        });
      }

      for (const match of file.content.matchAll(SWALLOWING_CATCH)) {
        const line = lineOf(file.content, match.index ?? 0);
        findings.push({
          id: `ST:cs-swallow-catch:${file.rel}:${line}`,
          rule: "no-swallowing-catch",
          category: "structure",
          rung: "R0",
          severity: "error",
          file: file.rel,
          line,
          message: "Empty C# catch block silently swallows exceptions.",
          fix: "Rethrow, return a typed result/error variant, or handle the specific expected exception explicitly.",
        });
      }

      for (const match of file.content.matchAll(CSHARP_DYNAMIC)) {
        const line = lineOf(file.content, match.index ?? 0);
        findings.push({
          id: `AS:cs-dynamic:${file.rel}:${line}`,
          rule: "no-chained-or-any-cast",
          category: "structure",
          rung: "R0",
          severity: "error",
          file: file.rel,
          line,
          message: `C# dynamic escape hatch (${match[0].trim()}) bypasses compile-time type safety.`,
          fix: "Model boundary payloads as typed records or JsonDocument parsed once at the edge.",
        });
      }

      for (const match of file.content.matchAll(CSHARP_PRAGMA_DISABLE)) {
        const tail = match[1] ?? "";
        if (!/(?:\/\/\s*(?:WARNING|SAFETY):|--\s*\S)/i.test(tail)) {
          const line = lineOf(file.content, match.index ?? 0);
          findings.push({
            id: `SU:cs-pragma:${file.rel}:${line}`,
            rule: "suppression-audit",
            category: "structure",
            rung: "R0",
            severity: "error",
            file: file.rel,
            line,
            message: "Unjustified #pragma warning disable suppresses compiler/analyzer checks.",
            fix: "Fix the diagnostic or attach an explicit // WARNING: or // SAFETY: justification.",
          });
        }
      }

      for (const match of file.content.matchAll(CSHARP_SUPPRESS_ATTR)) {
        const args = match[1] ?? "";
        if (!/Justification\s*=\s*"[^"]+"/.test(args)) {
          const line = lineOf(file.content, match.index ?? 0);
          findings.push({
            id: `SU:cs-suppress-attr:${file.rel}:${line}`,
            rule: "suppression-audit",
            category: "structure",
            rung: "R0",
            severity: "error",
            file: file.rel,
            line,
            message: "[SuppressMessage] without a non-empty Justification hides analyzer warnings.",
            fix: 'Fix the warning or supply Justification = "<concrete reason>".',
          });
        }
      }
    }

    if (file.language === "rust" && !file.isTest && !isGenerated) {
      const cfgTestIdx = file.content.search(/#\[cfg\(test\)\]/);
      const prodContent = cfgTestIdx >= 0 ? file.content.slice(0, cfgTestIdx) : file.content;
      const maskedProd = maskCode(prodContent, "rust");
      const prodLines = prodContent.split(/\r?\n/);

      for (const match of maskedProd.matchAll(RUST_TEST_ONLY_EXPORT)) {
        const line = lineOf(prodContent, match.index ?? 0);
        findings.push({
          id: `ST:rs-test-seam:${file.rel}:${line}`,
          rule: "no-test-only-production-seam",
          category: "structure",
          rung: "R1",
          severity: "warn",
          file: file.rel,
          line,
          message: `Test-only public function in Rust production file: ${match[0].trim()}.`,
          fix: "Remove test-only production exports and verify behavior through the public crate interface.",
        });
      }

      for (const match of maskedProd.matchAll(RUST_UNSAFE_OR_TRANSMUTE)) {
        const line = lineOf(prodContent, match.index ?? 0);
        const cur = prodLines[line - 1] ?? "";
        const prev = prodLines[line - 2] ?? "";
        if (!/SAFETY:/i.test(cur) && !/SAFETY:/i.test(prev)) {
          findings.push({
            id: `AS:rs-unsafe:${file.rel}:${line}`,
            rule: "rust-unjustified-unsafe",
            category: "structure",
            rung: "R0",
            severity: "error",
            file: file.rel,
            line,
            message: `Unjustified Rust safety escape hatch (${match[0].trim()}) without // SAFETY: invariant.`,
            fix: "Prefer safe typed conversions (TryFrom/From) or document the soundness invariant with // SAFETY:.",
          });
        }
      }

      for (const match of maskedProd.matchAll(RUST_SWALLOWING_ERR)) {
        const line = lineOf(prodContent, match.index ?? 0);
        findings.push({
          id: `ST:rs-swallow-err:${file.rel}:${line}`,
          rule: "no-swallowing-catch",
          category: "structure",
          rung: "R0",
          severity: "error",
          file: file.rel,
          line,
          message: "Empty Err(_) branch silently swallows Rust errors.",
          fix: "Propagate with ?, return a typed error variant, or handle the specific error explicitly.",
        });
      }

      if (!RUST_NON_PROD_HARNESS.test(file.rel)) {
        let unwrapCount = 0;
        for (const match of maskedProd.matchAll(RUST_PROD_UNWRAP)) {
          unwrapCount += 1;
          if (unwrapCount <= 5) {
            const line = lineOf(prodContent, match.index ?? 0);
            findings.push({
              id: `AS:rs-unwrap:${file.rel}:${line}`,
              rule: "rust-prod-unwrap-or-expect",
              category: "structure",
              rung: "R0",
              severity: "error",
              file: file.rel,
              line,
              message: `Production Rust ${match[0].trim()}) can panic at runtime instead of returning Result/Option.`,
              fix: "Return a typed Result/Option with ? or enforce clippy::unwrap_used = \"deny\" and clippy::expect_used = \"deny\".",
            });
          }
        }
      }

      for (const match of prodContent.matchAll(RUST_ALLOW_ATTR)) {
        const inner = match[1] ?? "";
        if (!/(?:clippy::|warnings|dead_code|unused)/i.test(inner)) continue;
        const line = lineOf(prodContent, match.index ?? 0);
        const cur = prodLines[line - 1] ?? "";
        const prev = prodLines[line - 2] ?? "";
        if (!/reason\s*=/.test(inner) && !/(?:WARNING|SAFETY):/i.test(cur) && !/(?:WARNING|SAFETY):/i.test(prev)) {
          findings.push({
            id: `SU:rs-allow:${file.rel}:${line}`,
            rule: "suppression-audit",
            category: "structure",
            rung: "R0",
            severity: "error",
            file: file.rel,
            line,
            message: `Unjustified ${match[0].trim()} suppresses compiler/Clippy lints.`,
            fix: 'Fix the warning or use #[expect(..., reason = "<invariant>")] with an explicit reason.',
          });
        }
      }
    }

    const baseLower = path.posix.basename(file.rel).toLowerCase();
    if (baseLower.endsWith(".csproj") || baseLower === "directory.build.props") {
      for (const match of file.content.matchAll(CSPROJ_WARN_FALSE)) {
        const line = lineOf(file.content, match.index ?? 0);
        findings.push({
          id: `CS:warn-false:${file.rel}:${line}`,
          rule: "csproj-warnings-not-errors",
          category: "cheat",
          rung: "R0",
          severity: "error",
          file: file.rel,
          line,
          message: "<TreatWarningsAsErrors>false</TreatWarningsAsErrors> weakens the C# static gate.",
          fix: "Set <TreatWarningsAsErrors>true</TreatWarningsAsErrors> in Directory.Build.props.",
        });
      }
      for (const match of file.content.matchAll(CSPROJ_NOWARN)) {
        const line = lineOf(file.content, match.index ?? 0);
        findings.push({
          id: `CS:nowarn:${file.rel}:${line}`,
          rule: "csproj-nowarn-suppression",
          category: "structure",
          rung: "R0",
          severity: "warn",
          file: file.rel,
          line,
          message: `<NoWarn>${(match[1] ?? "").trim()}</NoWarn> suppresses compiler/analyzer diagnostics project-wide.`,
          fix: "Fix the underlying diagnostics instead of adding global <NoWarn> suppressions.",
        });
      }
    }

    if ((file.language === "typescript" || file.language === "javascript") && !isGenerated) {
      let supCount = 0;
      for (const match of file.content.matchAll(SUPPRESSION_DIRECTIVE)) {
        supCount += 1;
        if (supCount <= 3) {
          const line = lineOf(file.content, match.index ?? 0);
          findings.push({
            id: `SU:suppression:${file.rel}:${line}`,
            rule: "suppression-audit",
            category: "structure",
            rung: "R0",
            severity: "warn",
            file: file.rel,
            line,
            message: "Blanket lint, type, or coverage suppression weakens deterministic gates.",
            fix: "Fix the underlying defect or scope to a specific rule under a shrink-only suppression ratchet.",
          });
        }
      }
    }

    if ((baseLower === "agents.md" || baseLower === "claude.md") && file.lines > MAX_AGENTS_LINES) {
      findings.push({
        id: `AH:long-instructions:${file.rel}`,
        rule: "agents-md-size",
        category: "oracle-lock",
        rung: "R0",
        severity: "warn",
        file: file.rel,
        line: 1,
        message: `${file.rel} is ${file.lines} lines (budget: <= ${MAX_AGENTS_LINES}).`,
        fix: "Promote mechanical rules to linters/hooks and move deep reference material into on-demand skill references.",
      });
    }
  }

  for (const [dir, members] of dirMembers.entries()) {
    if (dir === "." || dir.includes("fixtures") || GENERATED_PATH.test(`${dir}/`)) continue;
    if (members.size > WIDE_DIR_LIMIT) {
      findings.push({
        id: `ST:wide-dir:${dir}`,
        rule: "wide-directory",
        category: "structure",
        rung: "R1",
        severity: "warn",
        file: dir,
        line: 1,
        message: `Directory ${dir}/ holds ${members.size} entries (budget: <= ${WIDE_DIR_LIMIT}).`,
        fix: "Group related files into feature subdirectories so agents read rather than search listings.",
      });
    }
  }

  for (const [dir, names] of dirSourceFiles.entries()) {
    const prefixCounts = new Map<string, string[]>();
    for (const name of names) {
      const stem = name.replace(/\.[^.]+$/, "");
      const prefix = stem.split("-")[0] ?? "";
      if (prefix.length < 3 || !stem.includes("-")) continue;
      const list = prefixCounts.get(prefix) ?? [];
      list.push(name);
      prefixCounts.set(prefix, list);
    }
    for (const [prefix, list] of prefixCounts.entries()) {
      if (list.length >= 3) {
        findings.push({
          id: `ST:prefix-cluster:${dir}:${prefix}`,
          rule: "no-prefix-cluster",
          category: "structure",
          rung: "R1",
          severity: "warn",
          file: dir,
          line: 1,
          message: `${list.length} sibling modules in ${dir}/ share prefix "${prefix}-" (${list.slice(0, 4).join(", ")}).`,
          fix: `Group them into a ${dir === "." ? prefix : `${dir}/${prefix}`}/ feature folder with a narrow entry point.`,
        });
      }
    }
  }

  findings.push(...analyzeOracleAndInstructions(repo));
  findings.push(...analyzeStateMachines(repo));
  findings.push(...analyzeProdZeroDefectRules(repo));
  findings.push(...analyzePerfHygiene(repo));
  findings.push(...auditZeroDefectArtifacts(repo));

  return findings;
}
