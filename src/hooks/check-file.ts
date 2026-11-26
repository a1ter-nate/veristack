import fs from "node:fs";
import path from "node:path";
import { analyzeUniversalAntiSlopProd, analyzeUniversalLandminesTest } from "../anti-slop/oxc-antislop-landmines.ts";
import { analyzeUniversalBendLaws } from "../anti-slop/universal-laws.ts";
import { analyzeBlackHoleReplayGuards } from "../ast/blackhole-replay-guards.ts";
import { analyzeImmuneSystemGates } from "../ast/immune-gates.ts";
import { analyzeT3ProdGuards } from "../ast/t3-immune-rules.ts";
import { analyzeTsAstGuards, parseTsAst } from "../ast/ts-ast.ts";
import { analyzeWave5AiFirstGuards } from "../ast/wave5-ai-first.ts";
import { analyzeWave6TitansAGuards } from "../ast/wave6-titans-a.ts";
import { analyzeWave7TitansBGuards } from "../ast/wave7-titans-b.ts";
import { auditCiWorkflows } from "../ci-auditor.ts";
import { detectLanguage, type DiscoveredRepo, extractSfcScript, isTestFilePath, type ScannedFile } from "../discover.ts";
import { lintNoComments } from "../no-comments.ts";
import { analyzeProdZeroDefectRules } from "../prod-guards.ts";
import { lintImplicitStateMachinesInFile } from "../state-machines/index.ts";
import { analyzeStructure } from "../structure.ts";
import { lineOf, maskCode } from "../test-lexical.ts";
import type { Finding } from "../types.ts";
import { analyzeCveAndPostmortemGuards } from "../zero-defect/cve-and-agent-guards.ts";
import { analyzeOssGuards } from "../zero-defect/oss-guards.ts";
import { analyzePerfHygiene } from "../zero-defect/perf-lints.ts";
import { applyRepoConfig, loadRepoConfig } from "../zero-defect/repo-config.ts";
import { analyzeRuntimeGuards } from "../zero-defect/runtime-guards.ts";

export type CheckFileTier = "immediate" | "all";

export interface CheckFileOptions {
  repoRoot?: string;
  tier?: CheckFileTier;
  content?: string;
  strict?: boolean;
  maxLines?: number;
}

export interface CheckFileResult {
  file: string;
  tier: CheckFileTier;
  language: ScannedFile["language"] | null;
  elapsedMs: number;
  findings: Finding[];
}

const CHAINED_AS = /\bas\s+unknown\s+as\b|\bas\s+any\b/g;
const SWALLOWING_CATCH = /\bcatch\s*(?:\([^)]*\))?\s*\{\s*\}/g;
const CSHARP_DYNAMIC = /\bdynamic\s+[A-Za-z_][A-Za-z0-9_]*\b/g;
const PY_ANY_ESCAPE = /\bcast\s*\(\s*Any\b|:\s*Any\b|->\s*Any\b/g;
const PY_SWALLOWING_EXCEPT = /^\s*except(?:\s+[A-Za-z_][A-Za-z0-9_.]*(?:\s+as\s+[A-Za-z_][A-Za-z0-9_]*)?)?\s*:\s*\r?\n\s*pass\b/gm;
const RUST_SWALLOWING_ERR = /\bif\s+let\s+Err\s*\(\s*_\s*\)\s*=\s*[^\n{]+\{\s*\}|\bErr\s*\(\s*_\s*\)\s*=>\s*\{\s*\}/g;
const PROD_STRIPPED_ASSERT = /\bDebug\.Assert\s*\(|\bdebug_assert(?:_eq|_ne)?!\s*\(/g;
const PY_PROD_ASSERT = /^\s*assert\s+(?!_?never\b)/gm;
const TEST_SLEEP = /\b(?:setTimeout\s*\([^,]+,\s*\d+|waitForTimeout\s*\(|Thread\.Sleep\s*\(|Task\.Delay\s*\(|thread::sleep\s*\(|time\.sleep\s*\()/g;
const TEST_SKIP_ONLY = /\b(?:describe|it|test)\.(?:only|skip|todo|fixme)\s*\(|\[(?:Fact|Theory)\s*\([^\]]*\bSkip\s*=|\[Ignore\b|#\[ignore\b|@pytest\.mark\.skip\b/g;
const TEST_TAUTOLOGY = /\bexpect\s*\(\s*(?:true|false|\d+)\s*\)\s*\.\s*toBe\s*\(\s*(?:true|false|\d+)\s*\)|\bAssert\.(?:True\s*\(\s*true\s*\)|IsTrue\s*\(\s*true\s*\))|\bassert\s+True\b/g;
const TEST_COND_EXPECT = /\bif\s*\([^)]+\)\s*\{[^}]{0,160}\b(?:expect|assert|Assert\.)\s*\(/g;

function pushFast(
  findings: Finding[],
  file: ScannedFile,
  offset: number,
  rule: string,
  category: Finding["category"],
  rung: Finding["rung"],
  severity: Finding["severity"],
  message: string,
  fix: string,
): void {
  const line = lineOf(file.content, offset);
  findings.push({
    id: `HF:${rule}:${file.rel}:${line}`,
    rule,
    category,
    rung,
    severity,
    file: file.rel,
    line,
    message,
    fix,
  });
}

function scanImmediateProd(file: ScannedFile, code: string, findings: Finding[]): void {
  if (file.language === "typescript") {
    for (const m of code.matchAll(CHAINED_AS)) {
      pushFast(findings, file, m.index ?? 0, "no-chained-or-any-cast", "structure", "R0", "error", `Unsafe type escape hatch (${m[0]}) hides real contract.`, "Parse external data at the boundary with a schema or type guard instead of casting.");
    }
  }
  if (file.language === "typescript" || file.language === "javascript" || file.language === "csharp") {
    for (const m of code.matchAll(SWALLOWING_CATCH)) {
      pushFast(findings, file, m.index ?? 0, "no-swallowing-catch", "structure", "R0", "warn", "Empty catch block silently swallows errors.", "Rethrow, return a typed error, or handle the specific expected error explicitly.");
    }
  }
  if (file.language === "csharp") {
    for (const m of code.matchAll(CSHARP_DYNAMIC)) {
      pushFast(findings, file, m.index ?? 0, "no-chained-or-any-cast", "structure", "R0", "error", `C# dynamic binding (${m[0].trim()}) disables compile-time checking.`, "Use a concrete record, interface, or generic type parameter.");
    }
  }
  if (file.language === "python") {
    for (const m of code.matchAll(PY_ANY_ESCAPE)) {
      pushFast(findings, file, m.index ?? 0, "no-chained-or-any-cast", "structure", "R0", "error", `Python Any escape (${m[0].trim()}) disables static type checking.`, "Use object, Protocol, TypeVar, or a validated model.");
    }
    for (const m of code.matchAll(PY_SWALLOWING_EXCEPT)) {
      pushFast(findings, file, m.index ?? 0, "no-swallowing-catch", "structure", "R0", "error", "Python except-pass block silently swallows errors.", "Rethrow or handle the specific expected exception explicitly.");
    }
    for (const m of code.matchAll(PY_PROD_ASSERT)) {
      pushFast(findings, file, m.index ?? 0, "no-release-stripped-assert", "structure", "R1", "warn", "Bare Python assert in production code is stripped under python -O.", "Raise an explicit InvariantViolationError so invariants stay active in release.");
    }
  }
  if (file.language === "rust") {
    for (const m of code.matchAll(RUST_SWALLOWING_ERR)) {
      pushFast(findings, file, m.index ?? 0, "no-swallowing-catch", "structure", "R0", "error", "Empty Err(_) match arm silently swallows errors.", "Propagate with '?' or handle the error variant explicitly.");
    }
  }
  if (file.language === "csharp" || file.language === "rust") {
    for (const m of code.matchAll(PROD_STRIPPED_ASSERT)) {
      pushFast(findings, file, m.index ?? 0, "no-release-stripped-assert", "structure", "R1", "warn", "Debug assertion compiles out in Release builds.", "Use an always-on production invariant check.");
    }
  }
}

function scanImmediateTest(file: ScannedFile, code: string, findings: Finding[]): void {
  for (const m of code.matchAll(TEST_SLEEP)) {
    pushFast(findings, file, m.index ?? 0, "no-fixed-sleep", "cheat", "R0", "error", "Fixed sleep in test causes flakiness and slows CI.", "Await an explicit signal, completion promise, or web-first locator.");
  }
  for (const m of code.matchAll(TEST_SKIP_ONLY)) {
    pushFast(findings, file, m.index ?? 0, "test-discipline", "cheat", "R0", "error", "Skipped or focused test committed.", "Fix or delete the test instead of skipping or focusing it.");
  }
  for (const m of code.matchAll(TEST_TAUTOLOGY)) {
    pushFast(findings, file, m.index ?? 0, "weak-asserts-tautology", "test-smell", "R0", "error", "Tautological assertion cannot fail when behavior breaks.", "Assert computed SUT output against an independent expected value.");
  }
  for (const m of code.matchAll(TEST_COND_EXPECT)) {
    pushFast(findings, file, m.index ?? 0, "no-conditional-expect", "test-smell", "R0", "error", "Assertion inside conditional branch silently passes when skipped.", "Split into explicit cases with unconditional assertions.");
  }
}

function makeSingleFileRepo(repoRoot: string, file: ScannedFile): DiscoveredRepo {
  return {
    root: repoRoot,
    files: [file],
    allRelPaths: [file.rel],
    languages: file.language ? [file.language] : [],
    archetype: "library",
    observedArchetype: "library",
    scopeExclusions: [],
    signals: {
      hasFormatter: false, hasLinter: false, hasOxlint: false, hasAntiSlop: false, hasLandmines: false,
      hasGoInternal: false, hasDeslopPlease: false, hasDesloppify: false, hasStrictTypes: false, hasTsgo: false,
      hasKnipOrDeadCode: false, hasJscpd: false, hasArchFitness: false, hasPreCommitHook: false, hasCodeowners: false,
      hasReviewMd: false, hasAgentsMd: false, hasPbt: false, hasMbt: false, hasContractTool: false,
      hasComponentUiTool: false, hasMsw: false, hasMswStrict: false, hasTestcontainersOrRealDb: false,
      hasMigrationTest: false, hasBusDlqTest: false, hasDst: false, hasDryRun: false, hasMutationTool: false,
      hasFormalTool: false, hasFuzzTool: false, hasBombadil: false, hasVisualTool: false, hasPerfOrLoadTool: false,
      hasE2eTool: false, hasProdTelemetryOrCanary: false, hasDiffSelection: false,
    },
    ci: {
      hasCiWorkflows: false, workflowFiles: [], runsFormatterOrLint: false, runsTypeOrStructureCheck: false,
      runsUnitTests: false, runsBoundaryOrMbtTests: false, runsIntegrationOrDbTests: false, runsMutationOrFormal: false,
      runsPerfOrBench: false, runsE2eTests: false, runsProdVerification: false,
    },
  };
}

export function scanSingleFile(filePath: string, options: CheckFileOptions = {}): CheckFileResult {
  const started = performance.now();
  const repoRoot = path.resolve(options.repoRoot ?? process.cwd());
  const abs = path.isAbsolute(filePath) ? path.resolve(filePath) : path.resolve(repoRoot, filePath);
  const rel = path.relative(repoRoot, abs).split(path.sep).join("/");
  const tier: CheckFileTier = options.tier ?? "immediate";
  const maxLines = options.maxLines ?? 500;
  const language = detectLanguage(rel);

  let content = options.content;
  if (content === undefined) {
    if (!fs.existsSync(abs) || !fs.statSync(abs).isFile()) {
      throw new Error(`File not found: ${filePath}`);
    }
    content = fs.readFileSync(abs, "utf8");
  }

  const isSql = /\.sql$/i.test(rel);
  const isShell = /\.(?:sh|bash)$/i.test(rel);
  const isWorkflow =
    (rel.toLowerCase().startsWith(".github/workflows/") && /\.ya?ml$/i.test(rel)) ||
    /^(?:\.gitlab-ci\.yml|azure-pipelines\.yml|\.circleci\/config\.yml|bitbucket-pipelines\.yml)$/i.test(rel);
  const sfc = extractSfcScript(rel, content);
  const effectiveLang = language ?? sfc?.language;
  const effectiveContent = sfc ? sfc.content : content;

  if (!effectiveLang && !isSql && !isShell && !isWorkflow) {
    return { file: rel, tier, language: null, elapsedMs: Number((performance.now() - started).toFixed(2)), findings: [] };
  }

  const lines = content.length === 0 ? 0 : content.split(/\r?\n/).length;
  const file: ScannedFile = {
    rel,
    abs,
    language: effectiveLang,
    isTest: isTestFilePath(rel),
    isWorkflow,
    content: effectiveContent,
    ...(sfc ? { rawContent: content } : {}),
    lines,
  };

  const rawFindings: Finding[] = [];
  if (isWorkflow) {
    const singleRepo = makeSingleFileRepo(repoRoot, file);
    rawFindings.push(...auditCiWorkflows(singleRepo));
    rawFindings.push(...analyzeImmuneSystemGates(singleRepo));
  } else if (isSql) {
    if (/(?:^|\/)migrations?\//i.test(file.rel)) rawFindings.push(...analyzeCveAndPostmortemGuards(file));
    rawFindings.push(...analyzeWave6TitansAGuards(file));
    rawFindings.push(...analyzeWave7TitansBGuards(file));
  } else if (isShell) {
    rawFindings.push(...analyzeWave5AiFirstGuards(file));
    rawFindings.push(...analyzeWave7TitansBGuards(file));
    rawFindings.push(...analyzeBlackHoleReplayGuards(file));
    rawFindings.push(...analyzeT3ProdGuards(file));
  } else if (effectiveLang) {
    rawFindings.push(...lintNoComments(file.rel, file.content, effectiveLang));

    if (!file.isTest && file.lines > maxLines) {
      rawFindings.push({
        id: `HF:max-file-lines:${file.rel}:1`,
        rule: "max-file-lines",
        category: "structure",
        rung: "R1",
        severity: "warn",
        file: file.rel,
        line: 1,
        message: `${file.rel} has ${file.lines} lines (limit: ${maxLines}).`,
        fix: "Split cohesive responsibilities into deeper modules with narrow interfaces.",
      });
    }

    const code = maskCode(file.content, effectiveLang, !file.isTest);
    const ast = parseTsAst(file);

    if (file.isTest) {
      scanImmediateTest(file, code, rawFindings);
      rawFindings.push(...analyzeUniversalLandminesTest(file, code, ast));
    } else {
      scanImmediateProd(file, code, rawFindings);
      rawFindings.push(...lintImplicitStateMachinesInFile(file));
      rawFindings.push(...analyzeUniversalBendLaws(file));
      rawFindings.push(...analyzeUniversalAntiSlopProd(file, ast));
      rawFindings.push(...analyzeTsAstGuards(file, ast));
      if (tier === "all") {
        const singleRepo = makeSingleFileRepo(repoRoot, file);
        rawFindings.push(...analyzeStructure(singleRepo));
        rawFindings.push(...analyzeProdZeroDefectRules(singleRepo));
        rawFindings.push(...analyzeRuntimeGuards(file));
        rawFindings.push(...analyzeOssGuards(file));
        rawFindings.push(...analyzeCveAndPostmortemGuards(file));
        rawFindings.push(...analyzePerfHygiene(singleRepo));
      }
    }
  }

  const deduped = new Map<string, Finding>();
  for (const f of rawFindings) {
    const key = `${f.rule}:${f.file}:${f.line}`;
    if (!deduped.has(key)) deduped.set(key, f);
  }
  const unique = [...deduped.values()];
  const finalFindings = options.strict ? unique : applyRepoConfig(unique, loadRepoConfig(repoRoot)).findings;

  return {
    file: rel,
    tier,
    language,
    elapsedMs: Number((performance.now() - started).toFixed(2)),
    findings: finalFindings,
  };
}

export function formatSingleFileReport(result: CheckFileResult): string {
  if (result.findings.length === 0) {
    return `check-file (${result.tier}): ${result.file} — 0 issues (${result.elapsedMs}ms).`;
  }
  const out = [`check-file (${result.tier}): ${result.file} — ${result.findings.length} issue(s) (${result.elapsedMs}ms)`];
  for (const f of result.findings) {
    out.push(`  - [${f.severity.toUpperCase()}] ${f.rule} ${f.file}:${f.line} — ${f.message}`);
    out.push(`      Fix: ${f.fix}`);
  }
  return out.join("\n");
}
