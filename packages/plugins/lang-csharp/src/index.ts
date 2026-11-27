import path from "node:path";
import { lineOf, maskCode, Plugin, type Finding, type ScannedFile } from "@veristack/plugin";
import { lintCsharpStateMachines } from "./csharp-sm.ts";

export { lintCsharpStateMachines };

const SWALLOWING_CATCH = /\bcatch\s*(?:\([^)]*\))?\s*\{\s*\}/g;
const CSHARP_TEST_ONLY_EXPORT =
  /\b(?:public|internal)\s+(?:static\s+)?(?:async\s+)?[A-Za-z0-9_<>,.\s?]+\s+[A-Za-z0-9_]*(?:ForTesting|TestOnly|VisibleForTesting)\b/g;
const CSHARP_DYNAMIC = /\bdynamic\s+[A-Za-z_][A-Za-z0-9_]*\b/g;
const CSHARP_PRAGMA_DISABLE = /^\s*#pragma\s+warning\s+disable\b([^\n]*)/gm;
const CSHARP_SUPPRESS_ATTR = /\[SuppressMessage\s*\(([^)\]]+)\)\]/g;
const CSHARP_DEBUG_ASSERT = /\bDebug\.Assert\s*\(/g;
const CDC_WALL_CLOCK_CS = /\bDateTime(?:Offset)?\.(?:Utc)?Now\s*-\s*[A-Za-z_][A-Za-z0-9_.]*/g;
const CSPROJ_WARN_FALSE = /<TreatWarningsAsErrors>\s*false\s*<\/TreatWarningsAsErrors>/gi;
const CSPROJ_NOWARN = /<NoWarn>\s*([^<\s][^<]*)<\/NoWarn>/gi;

export function scanCSharpStructure(file: ScannedFile): Finding[] {
  if (!file.content || file.isTest) return [];
  const findings: Finding[] = [];
  const csharpCode = maskCode(file.content, "csharp");
  if (!csharpCode) return findings;
  for (const match of csharpCode.matchAll(CSHARP_TEST_ONLY_EXPORT)) {
    const line = lineOf(file.content, match.index ?? 0);
    findings.push({ id: `ST:cs-test-seam:${file.rel}:${line}`, rule: "no-test-only-production-seam", category: "structure", rung: "R1", severity: "warn", file: file.rel, line, message: `Test-only member detected in C# production file: ${match[0].trim()}.`, fix: "Remove test-only production backdoors and verify behavior through the public contract." });
  }
  for (const match of csharpCode.matchAll(SWALLOWING_CATCH)) {
    const line = lineOf(file.content, match.index ?? 0);
    findings.push({ id: `ST:cs-swallow-catch:${file.rel}:${line}`, rule: "no-swallowing-catch", category: "structure", rung: "R0", severity: "error", file: file.rel, line, message: "Empty C# catch block silently swallows exceptions.", fix: "Rethrow, return a typed result/error variant, or handle the specific expected exception explicitly." });
  }
  for (const match of csharpCode.matchAll(CSHARP_DYNAMIC)) {
    const line = lineOf(file.content, match.index ?? 0);
    findings.push({ id: `AS:cs-dynamic:${file.rel}:${line}`, rule: "no-chained-or-any-cast", category: "structure", rung: "R0", severity: "error", file: file.rel, line, message: `C# dynamic escape hatch (${match[0].trim()}) bypasses compile-time type safety.`, fix: "Model boundary payloads as typed records or JsonDocument parsed once at the edge." });
  }
  for (const match of file.content.matchAll(CSHARP_PRAGMA_DISABLE)) {
    if (/(?:\/\/\s*(?:WARNING|SAFETY):|--\s*\S)/i.test(match[1] ?? "")) continue;
    const line = lineOf(file.content, match.index ?? 0);
    findings.push({ id: `SU:cs-pragma:${file.rel}:${line}`, rule: "suppression-audit", category: "structure", rung: "R0", severity: "error", file: file.rel, line, message: "Unjustified #pragma warning disable suppresses compiler/analyzer checks.", fix: "Fix the diagnostic or attach an explicit // WARNING: or // SAFETY: justification." });
  }
  for (const match of file.content.matchAll(CSHARP_SUPPRESS_ATTR)) {
    if (/Justification\s*=\s*"[^"]+"/.test(match[1] ?? "")) continue;
    const line = lineOf(file.content, match.index ?? 0);
    findings.push({ id: `SU:cs-suppress-attr:${file.rel}:${line}`, rule: "suppression-audit", category: "structure", rung: "R0", severity: "error", file: file.rel, line, message: "[SuppressMessage] without a non-empty Justification hides analyzer warnings.", fix: 'Fix the warning or supply Justification = "<concrete reason>".' });
  }
  for (const match of csharpCode.matchAll(CSHARP_DEBUG_ASSERT)) {
    const line = lineOf(file.content, match.index ?? 0);
    findings.push({ id: `ZD:cs-debug-assert:${file.rel}:${line}`, rule: "no-release-stripped-assert", category: "structure", rung: "R1", severity: "warn", file: file.rel, line, message: "Debug.Assert compiles out in Release builds (violates Runtime Jidoka V36).", fix: "Use an always-on production invariant guard (e.g., Invariant.Require / InvalidOperationException)." });
  }
  for (const match of csharpCode.matchAll(CDC_WALL_CLOCK_CS)) {
    if (/(?:retention|ttl|window|max_?age|lookback|stale|grace|cooldown|expir|cutoff|days?_?ms|hours?_?ms|minutes?_?ms|seconds?_?ms|interval_?ms)/i.test(match[0])) continue;
    const line = lineOf(file.content, match.index ?? 0);
    findings.push({ id: `ZD:cdc-clock:${file.rel}:${line}`, rule: "cdc-wall-clock-duration", category: "structure", rung: "R1", severity: "warn", file: file.rel, line, message: `Wall-clock timestamp used for duration/elapsed math (${match[0].trim()}) breaks on NTP jumps or DST (V30 Clock CDC).`, fix: "Use a monotonic clock (TimeProvider.GetTimestamp / Stopwatch.GetTimestamp)." });
  }
  return findings;
}

export function scanCsprojConfig(file: ScannedFile): Finding[] {
  const baseLower = path.posix.basename(file.rel).toLowerCase();
  if (!baseLower.endsWith(".csproj") && baseLower !== "directory.build.props") return [];
  const findings: Finding[] = [];
  for (const match of file.content.matchAll(CSPROJ_WARN_FALSE)) {
    const line = lineOf(file.content, match.index ?? 0);
    findings.push({ id: `CS:warn-false:${file.rel}:${line}`, rule: "csproj-warnings-not-errors", category: "cheat", rung: "R0", severity: "error", file: file.rel, line, message: "<TreatWarningsAsErrors>false</TreatWarningsAsErrors> weakens the C# static gate.", fix: "Set <TreatWarningsAsErrors>true</TreatWarningsAsErrors> in Directory.Build.props." });
  }
  for (const match of file.content.matchAll(CSPROJ_NOWARN)) {
    const line = lineOf(file.content, match.index ?? 0);
    findings.push({ id: `CS:nowarn:${file.rel}:${line}`, rule: "csproj-nowarn-suppression", category: "structure", rung: "R0", severity: "warn", file: file.rel, line, message: `<NoWarn>${(match[1] ?? "").trim()}</NoWarn> suppresses compiler/analyzer diagnostics project-wide.`, fix: "Fix the underlying diagnostics instead of adding global <NoWarn> suppressions." });
  }
  return findings;
}

export const langCsharpPlugin = Plugin.define({
  id: "veristack.plugin.lang-csharp",
  setup(ctx) {
    ctx.language.transform((ed) => {
      ed.add({
        id: "csharp",
        extensions: [".cs", ".csx"],
        scanStructure: scanCSharpStructure,
        scanStateMachines: lintCsharpStateMachines,
      });
    });
    ctx.analyzer.transform((ed) => {
      ed.add({
        id: "veristack.csharp.csproj",
        phase: "lint",
        run: (runCtx) => runCtx.repo.files.flatMap((f) => scanCsprojConfig(f)),
      });
    });
  },
});

export default langCsharpPlugin;
