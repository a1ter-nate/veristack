import { analyzeUniversalAntiSlopProd } from "./anti-slop/oxc-antislop-landmines.ts";
import { analyzeUniversalBendLaws } from "./anti-slop/universal-laws.ts";
import { analyzeBlackHoleReplayGuards } from "./ast/blackhole-replay-guards.ts";
import { analyzeBlackHoleArchGates } from "./ast/cross-file-graph.ts";
import { analyzeDeviantInvariants } from "./ast/deviant-invariants.ts";
import { analyzeImmuneSystemGates } from "./ast/immune-gates.ts";
import { analyzeInvariantGuards } from "./ast/invariant-loss.ts";
import { analyzeLinearObligations } from "./ast/linear-obligations.ts";
import { analyzeT3ProdGuards } from "./ast/t3-immune-rules.ts";
import { analyzeTsAstGuards, parseTsAst } from "./ast/ts-ast.ts";
import { analyzeWave5AiFirstGuards } from "./ast/wave5-ai-first.ts";
import { analyzeWave6TitansAGuards } from "./ast/wave6-titans-a.ts";
import { analyzeWave7TitansBGuards } from "./ast/wave7-titans-b.ts";
import { type DiscoveredRepo, isDeclarationStub } from "./discover.ts";
import { lineOf, maskCode } from "./test-lexical.ts";
import type { Finding } from "./types.ts";
import { analyzeCveAndPostmortemGuards } from "./zero-defect/cve-and-agent-guards.ts";
import { analyzeEcosystemGuards } from "./zero-defect/ecosystem-guards.ts";
import { analyzeOssGuards } from "./zero-defect/oss-guards.ts";
import { analyzeRuntimeGuards } from "./zero-defect/runtime-guards.ts";

const GENERATED_PATH = /(?:^|\/)(?:generated|generated-clients?|codegen|__snapshots__)\/|\.(?:gen|generated)\.[cm]?[jt]sx?$/i;
const GENERATED_HEADER = /(?:@generated|auto-generated|do\s+not\s+edit|generated\s+by\b)/i;

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
const CATCH_OPEN = /\bcatch\s*(?:\([^)]*\))?\s*\{/g;
const SHAM_SUCCESS_RETURN = /\breturn\s*(?:true|(?:(?:Results\.|TypedResults\.)?Ok|new\s+OkObjectResult|new\s+JsonResult|NextResponse\.json|Response\.json|res\.(?:status\s*\(\s*200\s*\)\.)?json)\s*\(\s*(?:new\s*)?\{[^}]{0,160}\b(?:accepted|ok|success)\s*[:=]\s*true\b[^}]*\}\s*\)|\{[^}]{0,160}\b(?:accepted|ok|success)\s*:\s*true\b[^}]*\})\s*;|(?:const|let|var)\s+([A-Za-z_$]\w*)\s*=\s*\{[^}]{0,160}\b(?:accepted|ok|success)\s*:\s*true\b[^}]*\}[\s\S]{0,120}\breturn\s+\1\b/i;
const CATCHALL_SUCCESS_STUB = /\bdefault\s*:\s*\{?\s*return\s*(?:(?:Results\.|TypedResults\.)?Ok\s*\(\s*new\s*|new\s+OkObjectResult\s*\(\s*new\s*|NextResponse\.json\s*\(|Response\.json\s*\(|res\.(?:status\s*\(\s*200\s*\)\.)?json\s*\()?\{[^}]{0,120}\b(?:accepted|ok|success)\s*[:=]\s*true\b/g;
const PY_EXCEPT_OR_CASE_HEAD = /^([ \t]*)(except\b[^\n:]*|case\s+_)\s*:/gm;
const PY_SHAM_RETURN = /\breturn\s+(?:True|(?:JSONResponse\s*\(\s*)?\{[^\n}]*(?:["'](?:accepted|ok|success)["']\s*:\s*True|["']status["']\s*:\s*["']ok["'])[^\n}]*\})|([A-Za-z_]\w*)\s*=\s*\{[^\n}]*(?:["'](?:accepted|ok|success)["']\s*:\s*True|["']status["']\s*:\s*["']ok["'])[^\n}]*\}[\s\S]{0,120}\breturn\s+\1\b/;

function extractBalancedBraceBody(masked: string, raw: string, openBraceIdx: number): string {
  let depth = 0;
  for (let i = openBraceIdx; i < masked.length && i < openBraceIdx + 1200; i++) {
    if (masked[i] === "{") depth += 1;
    else if (masked[i] === "}" && --depth === 0) return raw.slice(openBraceIdx, i + 1);
  }
  return "";
}

function extractPyIndentBlock(raw: string, afterColonIdx: number, baseIndent: number): string {
  const lines = raw.slice(afterColonIdx).split(/\r?\n/).slice(1, 20);
  const body: string[] = [];
  for (const l of lines) {
    if (!l.trim()) { body.push(l); continue; }
    const ind = l.search(/\S/);
    if (ind <= baseIndent) break;
    body.push(l);
  }
  return body.join("\n");
}

function analyzePythonProdGuards(file: DiscoveredRepo["files"][number], raw: string, masked: string, findings: Finding[]): void {
  if (!raw) return;
  if (!masked) return;
  for (const match of masked.matchAll(PY_TEST_ONLY_EXPORT)) {
    const line = lineOf(raw, match.index ?? 0);
    findings.push({ id: `ST:py-test-seam:${file.rel}:${line}`, rule: "no-test-only-production-seam", category: "structure", rung: "R1", severity: "warn", file: file.rel, line, message: `Test-only function in Python production module: ${match[0].trim()}.`, fix: "Remove test-only production backdoors and verify behavior through the public API." });
  }
  const seenPyAnyLines = new Set<number>();
  for (const match of masked.matchAll(PY_ANY_ESCAPE)) {
    const line = lineOf(raw, match.index ?? 0);
    if (seenPyAnyLines.has(line)) continue;
    seenPyAnyLines.add(line);
    findings.push({ id: `AS:py-any:${file.rel}:${line}`, rule: "no-chained-or-any-cast", category: "structure", rung: "R0", severity: "error", file: file.rel, line, message: `Python Any type escape hatch (${match[0].trim()}) disables static type safety.`, fix: "Use object, Protocol, TypeVar, or a validated dataclass/Pydantic model at the boundary." });
  }
  for (const match of raw.matchAll(PY_EXCEPT_OR_CASE_HEAD)) {
    const idx = match.index ?? 0;
    if (masked[idx + (match[1]?.length ?? 0)] === " ") continue;
    const block = extractPyIndentBlock(raw, idx + match[0].length, (match[1] ?? "").length);
    if (!PY_SHAM_RETURN.test(block)) continue;
    const line = lineOf(raw, idx);
    const isCase = (match[2] ?? "").startsWith("case");
    findings.push({
      id: `SHAM:py-${isCase ? "catchall" : "except"}:${file.rel}:${line}`,
      rule: isCase ? "no-catchall-success-stub" : "no-silent-catch-return",
      category: "cheat",
      rung: "R0",
      severity: "error",
      file: file.rel,
      line,
      message: isCase ? "Python wildcard 'case _:' returns fabricated success (True / {'accepted': True})." : "Python except block swallows an exception and returns fabricated success.",
      fix: "Rethrow or return an explicit typed error instead of synthetic success.",
    });
  }
  for (const match of masked.matchAll(PY_SWALLOWING_EXCEPT)) {
    const line = lineOf(raw, match.index ?? 0);
    findings.push({ id: `ST:py-swallow:${file.rel}:${line}`, rule: "no-swallowing-catch", category: "structure", rung: "R0", severity: "error", file: file.rel, line, message: "Python except-pass block silently swallows errors.", fix: "Rethrow, return a typed failure variant, or handle the specific expected exception explicitly." });
  }
  for (const match of raw.matchAll(PY_BARE_SUPPRESSION)) {
    const line = lineOf(raw, match.index ?? 0);
    findings.push({ id: `SU:py-bare:${file.rel}:${line}`, rule: "suppression-audit", category: "structure", rung: "R0", severity: "error", file: file.rel, line, message: "Bare '# type: ignore' or '# noqa' without an error code and concrete reason.", fix: "Fix the diagnostic or scope to a specific code with an inline reason." });
  }
  for (const match of masked.matchAll(PY_PROD_ASSERT)) {
    const line = lineOf(raw, match.index ?? 0);
    findings.push({ id: `ZD:py-assert:${file.rel}:${line}`, rule: "no-release-stripped-assert", category: "structure", rung: "R1", severity: "warn", file: file.rel, line, message: "Python bare 'assert' in production code is stripped under 'python -O' (violates Runtime Jidoka V36).", fix: "Raise an explicit InvariantViolationError (e.g., if not cond: raise InvariantViolationError(...)) so invariants stay active in release." });
  }
}

function analyzeAssertClockAndLoopGuards(file: DiscoveredRepo["files"][number], raw: string, masked: string, findings: Finding[]): void {
  if (!raw) return;
  if (!masked) return;
  if (file.language === "csharp") {
    for (const match of masked.matchAll(CSHARP_DEBUG_ASSERT)) {
      const line = lineOf(raw, match.index ?? 0);
      findings.push({ id: `ZD:cs-debug-assert:${file.rel}:${line}`, rule: "no-release-stripped-assert", category: "structure", rung: "R1", severity: "warn", file: file.rel, line, message: "Debug.Assert compiles out in Release builds (violates Runtime Jidoka V36).", fix: "Use an always-on production invariant guard (e.g., Invariant.Require / InvalidOperationException)." });
    }
  }
  if (file.language === "rust") {
    for (const match of masked.matchAll(RUST_DEBUG_ASSERT)) {
      const line = lineOf(raw, match.index ?? 0);
      findings.push({ id: `ZD:rs-debug-assert:${file.rel}:${line}`, rule: "no-release-stripped-assert", category: "structure", rung: "R1", severity: "warn", file: file.rel, line, message: "debug_assert! is stripped in --release builds (violates Runtime Jidoka V36 for corruption-critical invariants).", fix: "Use release-active assert! or return a typed invariant error variant." });
    }
  }
  const cdcRegex =
    file.language === "typescript" || file.language === "javascript" ? CDC_WALL_CLOCK_TS
      : file.language === "csharp" ? CDC_WALL_CLOCK_CS
      : file.language === "rust" ? CDC_WALL_CLOCK_RS
      : file.language === "python" ? CDC_WALL_CLOCK_PY : undefined;
  if (cdcRegex) {
    for (const match of masked.matchAll(cdcRegex)) {
      if (/(?:retention|ttl|window|max_?age|lookback|stale|grace|cooldown|expir|cutoff|days?_?ms|hours?_?ms|minutes?_?ms|seconds?_?ms|interval_?ms)/i.test(match[0])) continue;
      const line = lineOf(raw, match.index ?? 0);
      findings.push({ id: `ZD:cdc-clock:${file.rel}:${line}`, rule: "cdc-wall-clock-duration", category: "structure", rung: "R1", severity: "warn", file: file.rel, line, message: `Wall-clock timestamp used for duration/elapsed math (${match[0].trim()}) breaks on NTP jumps or DST (V30 Clock CDC).`, fix: "Use a monotonic clock (performance.now / TimeProvider.GetTimestamp / std::time::Instant / time.monotonic)." });
    }
  }
  for (const match of masked.matchAll(UNBOUNDED_LOOP)) {
    const idx = match.index ?? 0;
    const window = masked.slice(Math.max(0, idx - 220), idx + 450);
    if (
      /\b(?:maxIter|max_iter|maxAttempts|max_attempts|maxRetries|max_retries|maxPages|max_pages|deadline|timeout|limit|fuel|budget|countdown)\b/i.test(window) ||
      /\b(?:if\s*\([^)]*(?:done|eof|empty|null|err)|if\s*\(\s*!\s*[A-Za-z_$][A-Za-z0-9_$.]*\s*\)|if\s+not\s+\w+|if\s+\w+\s+is\s+None\b|if\s+[A-Za-z_]\w*\s*>=\s*[^\n{]+\.len\s*\(|Err\s*\([^)]*\)\s*=>|None\s*=>)[\s\S]{0,60}\b(?:break|return)\b/i.test(window)
    ) continue;
    const line = lineOf(raw, idx);
    findings.push({ id: `ZD:unbounded-loop:${file.rel}:${line}`, rule: "unbounded-loop-risk", category: "structure", rung: "R1", severity: "warn", file: file.rel, line, message: `Unbounded loop (${match[0].trim()}) has no visible static iteration cap or fuel bound (V31 JPL Power of 10).`, fix: "Bound the loop with an explicit maxIterations/fuel ceiling or finite iterator." });
  }
}

function analyzeShamCatchGuards(file: DiscoveredRepo["files"][number], raw: string, masked: string, findings: Finding[]): void {
  if (file.language !== "typescript" && file.language !== "javascript" && file.language !== "csharp") return;
  for (const match of masked.matchAll(CATCH_OPEN)) {
    const idx = match.index ?? 0;
    const block = extractBalancedBraceBody(masked, raw, idx + match[0].length - 1);
    if (!block || !SHAM_SUCCESS_RETURN.test(block)) continue;
    const line = lineOf(raw, idx);
    findings.push({ id: `SHAM:silent-catch-ret:${file.rel}:${line}`, rule: "no-silent-catch-return", category: "cheat", rung: "R0", severity: "error", file: file.rel, line, message: "Catch block swallows an exception and returns a fabricated success value (true / { ok/accepted: true }).", fix: "Rethrow, return a typed error variant, or surface the failure explicitly instead of returning synthetic success." });
  }
  for (const match of raw.matchAll(CATCHALL_SUCCESS_STUB)) {
    const idx = match.index ?? 0;
    if (masked[idx] === " ") continue;
    const line = lineOf(raw, idx);
    findings.push({ id: `SHAM:catchall-ok:${file.rel}:${line}`, rule: "no-catchall-success-stub", category: "cheat", rung: "R0", severity: "error", file: file.rel, line, message: "Default/catch-all branch fabricates an accepted/ok: true success response for unknown actions/events.", fix: "Reject unknown actions/events explicitly (4xx / typed error) instead of returning synthetic success." });
  }
}

function analyzeSingleProdFile(file: DiscoveredRepo["files"][number], findings: Finding[]): void {
  if (file.rel.endsWith(".sql")) {
    if (/(?:^|\/)migrations?\//i.test(file.rel)) findings.push(...analyzeCveAndPostmortemGuards(file));
    findings.push(...analyzeWave6TitansAGuards(file), ...analyzeWave7TitansBGuards(file));
    return;
  }
  if (/\.(?:sh|bash)$/i.test(file.rel)) {
    findings.push(...analyzeWave5AiFirstGuards(file), ...analyzeWave7TitansBGuards(file), ...analyzeBlackHoleReplayGuards(file), ...analyzeT3ProdGuards(file));
    return;
  }
  const isStub = Boolean(file.isStub) || isDeclarationStub(file.rel);
  if (!file.language || file.isTest || isStub || (GENERATED_PATH.test(file.rel) && GENERATED_HEADER.test(file.content.slice(0, 600)))) return;
  const raw = file.content;
  const masked = maskCode(raw, file.language, true);
  if (file.language === "python") analyzePythonProdGuards(file, raw, masked, findings);
  analyzeAssertClockAndLoopGuards(file, raw, masked, findings);
  analyzeShamCatchGuards(file, raw, masked, findings);
  const ast = parseTsAst(file);
  findings.push(
    ...analyzeRuntimeGuards(file), ...analyzeOssGuards(file), ...analyzeCveAndPostmortemGuards(file),
    ...analyzeWave5AiFirstGuards(file), ...analyzeWave6TitansAGuards(file), ...analyzeWave7TitansBGuards(file),
    ...analyzeUniversalBendLaws(file), ...analyzeUniversalAntiSlopProd(file, ast), ...analyzeTsAstGuards(file, ast),
    ...analyzeLinearObligations(file, ast), ...analyzeBlackHoleReplayGuards(file, ast), ...analyzeT3ProdGuards(file, ast),
    ...analyzeInvariantGuards(file),
  );
}

export function analyzeProdZeroDefectRules(repo: DiscoveredRepo): Finding[] {
  if (!repo.root) throw new Error("Repo root is required.");
  const findings: Finding[] = [];
  if (repo.files.length === 0) return findings;
  for (const file of repo.files) analyzeSingleProdFile(file, findings);
  findings.push(
    ...analyzeEcosystemGuards(repo),
    ...analyzeBlackHoleArchGates(repo),
    ...analyzeImmuneSystemGates(repo),
    ...analyzeDeviantInvariants(repo),
  );
  return findings;
}
