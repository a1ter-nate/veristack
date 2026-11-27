import { lineOf, maskCode, Plugin, type Finding, type ScannedFile } from "@veristack/plugin";
import { lintRustStateMachines } from "./rust-sm.ts";

export { lintRustStateMachines };

const RUST_NON_PROD_HARNESS = /(?:^|\/)(?:tests\/(?:support|helpers|fixtures|mocks|stubs)|fuzz|benches)\//i;
const RUST_TEST_ONLY_EXPORT = /\bpub(?:\([^)]*\))?\s+fn\s+[a-zA-Z0-9_]*(?:_for_testing|_test_only)\b/g;
const RUST_UNSAFE_OR_TRANSMUTE = /\bstd::mem::transmute\b|\bmem::transmute\b|\bunsafe\s*\{/g;
const RUST_SWALLOWING_ERR = /\bif\s+let\s+Err\s*\(\s*_\s*\)\s*=\s*[^\n{]+\{\s*\}|\bErr\s*\(\s*_\s*\)\s*=>\s*\{\s*\}/g;
const RUST_PROD_UNWRAP = /\.\s*(?:unwrap|expect)\s*\(/g;
const RUST_ALLOW_ATTR = /#!?\s*\[\s*allow\s*\(([^)]+)\)\s*\]/g;
const RUST_DEBUG_ASSERT = /\bdebug_assert(?:_eq|_ne)?!\s*\(/g;
const CDC_WALL_CLOCK_RS = /\bSystemTime::now\s*\(\s*\)\s*\.duration_since\b|\b(?:Utc|Local)::now\s*\(\s*\)\s*-\s*[A-Za-z_]/g;

export function scanRustStructure(file: ScannedFile): Finding[] {
  if (!file.content || file.isTest) return [];
  const findings: Finding[] = [];
  const maskedProd = maskCode(file.content, "rust", true);
  if (!maskedProd) return findings;
  const prodContent = file.content;
  const prodLines = prodContent.split(/\r?\n/);

  for (const match of maskedProd.matchAll(RUST_TEST_ONLY_EXPORT)) {
    const line = lineOf(prodContent, match.index ?? 0);
    findings.push({ id: `ST:rs-test-seam:${file.rel}:${line}`, rule: "no-test-only-production-seam", category: "structure", rung: "R1", severity: "warn", file: file.rel, line, message: `Test-only public function in Rust production file: ${match[0].trim()}.`, fix: "Remove test-only production exports and verify behavior through the public crate interface." });
  }
  for (const match of maskedProd.matchAll(RUST_UNSAFE_OR_TRANSMUTE)) {
    const line = lineOf(prodContent, match.index ?? 0);
    if (/SAFETY:/i.test(prodLines[line - 1] ?? "") || /SAFETY:/i.test(prodLines[line - 2] ?? "")) continue;
    findings.push({ id: `AS:rs-unsafe:${file.rel}:${line}`, rule: "rust-unjustified-unsafe", category: "structure", rung: "R0", severity: "error", file: file.rel, line, message: `Unjustified Rust safety escape hatch (${match[0].trim()}) without // SAFETY: invariant.`, fix: "Prefer safe typed conversions (TryFrom/From) or document the soundness invariant with // SAFETY:." });
  }
  for (const match of maskedProd.matchAll(RUST_SWALLOWING_ERR)) {
    const line = lineOf(prodContent, match.index ?? 0);
    findings.push({ id: `ST:rs-swallow-err:${file.rel}:${line}`, rule: "no-swallowing-catch", category: "structure", rung: "R0", severity: "error", file: file.rel, line, message: "Empty Err(_) branch silently swallows Rust errors.", fix: "Propagate with ?, return a typed error variant, or handle the specific error explicitly." });
  }
  if (!RUST_NON_PROD_HARNESS.test(file.rel)) {
    let unwrapCount = 0;
    for (const match of maskedProd.matchAll(RUST_PROD_UNWRAP)) {
      if (++unwrapCount > 5) break;
      const line = lineOf(prodContent, match.index ?? 0);
      findings.push({ id: `AS:rs-unwrap:${file.rel}:${line}`, rule: "rust-prod-unwrap-or-expect", category: "structure", rung: "R0", severity: "error", file: file.rel, line, message: `Production Rust ${match[0].trim()}) can panic at runtime instead of returning Result/Option.`, fix: 'Return a typed Result/Option with ? or enforce clippy::unwrap_used = "deny" and clippy::expect_used = "deny".' });
    }
  }
  for (const match of prodContent.matchAll(RUST_ALLOW_ATTR)) {
    if (maskedProd[match.index ?? 0] === " ") continue;
    const inner = match[1] ?? "";
    if (!/(?:clippy::|warnings|dead_code|unused)/i.test(inner)) continue;
    const line = lineOf(prodContent, match.index ?? 0);
    if (/reason\s*=/.test(inner) || /(?:WARNING|SAFETY):/i.test(prodLines[line - 1] ?? "") || /(?:WARNING|SAFETY):/i.test(prodLines[line - 2] ?? "")) continue;
    findings.push({ id: `SU:rs-allow:${file.rel}:${line}`, rule: "suppression-audit", category: "structure", rung: "R0", severity: "error", file: file.rel, line, message: `Unjustified ${match[0].trim()} suppresses compiler/Clippy lints.`, fix: 'Fix the warning or use #[expect(..., reason = "<invariant>")] with an explicit reason.' });
  }
  for (const match of maskedProd.matchAll(RUST_DEBUG_ASSERT)) {
    const line = lineOf(prodContent, match.index ?? 0);
    findings.push({ id: `ZD:rs-debug-assert:${file.rel}:${line}`, rule: "no-release-stripped-assert", category: "structure", rung: "R1", severity: "warn", file: file.rel, line, message: "debug_assert! is stripped in --release builds (violates Runtime Jidoka V36 for corruption-critical invariants).", fix: "Use release-active assert! or return a typed invariant error variant." });
  }
  for (const match of maskedProd.matchAll(CDC_WALL_CLOCK_RS)) {
    if (/(?:retention|ttl|window|max_?age|lookback|stale|grace|cooldown|expir|cutoff|days?_?ms|hours?_?ms|minutes?_?ms|seconds?_?ms|interval_?ms)/i.test(match[0])) continue;
    const line = lineOf(prodContent, match.index ?? 0);
    findings.push({ id: `ZD:cdc-clock:${file.rel}:${line}`, rule: "cdc-wall-clock-duration", category: "structure", rung: "R1", severity: "warn", file: file.rel, line, message: `Wall-clock timestamp used for duration/elapsed math (${match[0].trim()}) breaks on NTP jumps or DST (V30 Clock CDC).`, fix: "Use a monotonic clock (std::time::Instant)." });
  }
  return findings;
}

export const langRustPlugin = Plugin.define({
  id: "veristack.plugin.lang-rust",
  setup(ctx) {
    ctx.language.transform((ed) => {
      ed.add({
        id: "rust",
        extensions: [".rs"],
        scanStructure: scanRustStructure,
        scanStateMachines: lintRustStateMachines,
      });
    });
  },
});

export default langRustPlugin;
