import fs from "node:fs";
import path from "node:path";
import { analyzeImmuneSystemGates } from "@veristack/plugin-control-plane";
import { analyzeBlackHoleReplayGuards, analyzeT3ProdGuards, analyzeTsAstGuards, analyzeWave5AiFirstGuards, analyzeWave6TitansAGuards, analyzeWave7TitansBGuards, extractSfcScript, hasPathologicalNesting, parseTsAst } from "@veristack/plugin-lang-typescript";
import { auditCiWorkflows } from "@veristack/plugin-ci-auditor";
import { analyzeStructure, analyzeTests, analyzeUniversalAntiSlopProd, analyzeUniversalBendLaws, analyzeUniversalLandminesTest, lintNoComments } from "@veristack/plugin-anti-slop";
import { lintImplicitStateMachinesInFile } from "@veristack/plugin-state-machines";
import { applyRepoConfig, createEmptyCiSignals, createEmptySignals, lineOf, loadRepoConfig, maskCode, pathHelpers, type CheckFileOptions, type CheckFileResult, type CheckFileTier, type DiscoveredRepo, type Finding, type Language, type ScannedFile } from "@veristack/plugin";
import { analyzeCveAndPostmortemGuards, analyzeOssGuards, analyzePerfHygiene, analyzeRuntimeGuards } from "@veristack/plugin-zero-defect";

function detectLanguageFast(rel: string): Language | undefined {
  const lower = rel.toLowerCase();
  if (lower.endsWith(".ts") || lower.endsWith(".tsx") || lower.endsWith(".mts") || lower.endsWith(".cts")) return "typescript";
  if (lower.endsWith(".js") || lower.endsWith(".jsx") || lower.endsWith(".mjs") || lower.endsWith(".cjs")) return "javascript";
  if (lower.endsWith(".cs") || lower.endsWith(".csx")) return "csharp";
  if (lower.endsWith(".py") || lower.endsWith(".pyi")) return "python";
  if (lower.endsWith(".rs")) return "rust";
  if (lower.endsWith(".go")) return "go";
  return undefined;
}

const CHAINED_AS = /\bas\s+unknown\s+as\b|\bas\s+any\b/g;

function findEmptyCatchOffsets(code: string): number[] {
  const offsets: number[] = [];
  let idx = 0;
  while ((idx = code.indexOf("catch", idx)) >= 0) {
    const prev = idx > 0 ? (code[idx - 1] ?? "") : "";
    const afterWord = code[idx + 5] ?? "";
    if (/[A-Za-z0-9_$]/.test(prev) || /[A-Za-z0-9_$]/.test(afterWord)) { idx += 5; continue; }
    let p = idx + 5;
    while (p < code.length && /\s/.test(code[p] ?? "")) p += 1;
    if (code[p] === "(") {
      let depth = 1;
      p += 1;
      while (p < code.length && depth > 0) {
        if (code[p] === "(") depth += 1;
        else if (code[p] === ")") depth -= 1;
        p += 1;
      }
      while (p < code.length && /\s/.test(code[p] ?? "")) p += 1;
    }
    if (code[p] === "{") {
      p += 1;
      while (p < code.length && (/\s/.test(code[p] ?? "") || code[p] === ";")) p += 1;
      if (code[p] === "}") offsets.push(idx);
    }
    idx = Math.max(idx + 5, p);
  }
  return offsets;
}
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

interface FastFindingSpec {
  file: ScannedFile;
  offset: number;
  rule: string;
  category: Finding["category"];
  rung: Finding["rung"];
  severity: Finding["severity"];
  message: string;
  fix: string;
}

function pushFast(findings: Finding[], spec: FastFindingSpec): void {
  const line = lineOf(spec.file.content, spec.offset);
  findings.push({
    id: `HF:${spec.rule}:${spec.file.rel}:${line}`,
    rule: spec.rule,
    category: spec.category,
    rung: spec.rung,
    severity: spec.severity,
    file: spec.file.rel,
    line,
    message: spec.message,
    fix: spec.fix,
  });
}

function scanImmediateProd(file: ScannedFile, code: string, findings: Finding[]): void {
  if (!file.language) return;
  if (!code) return;
  if (file.language === "typescript") {
    for (const m of code.matchAll(CHAINED_AS)) {
      pushFast(findings, { file, offset: m.index ?? 0, rule: "no-chained-or-any-cast", category: "structure", rung: "R0", severity: "error", message: `Unsafe type escape hatch (${m[0]}) hides real contract.`, fix: "Parse external data at the boundary with a schema or type guard instead of casting." });
    }
  }
  if (file.language === "typescript" || file.language === "javascript" || file.language === "csharp") {
    for (const off of findEmptyCatchOffsets(code)) {
      pushFast(findings, { file, offset: off, rule: "no-swallowing-catch", category: "structure", rung: "R0", severity: "warn", message: "Empty catch block silently swallows errors.", fix: "Rethrow, return a typed error, or handle the specific expected error explicitly." });
    }
  }
  if (file.language === "csharp") {
    for (const m of code.matchAll(CSHARP_DYNAMIC)) {
      pushFast(findings, { file, offset: m.index ?? 0, rule: "no-chained-or-any-cast", category: "structure", rung: "R0", severity: "error", message: `C# dynamic binding (${m[0].trim()}) disables compile-time checking.`, fix: "Use a concrete record, interface, or generic type parameter." });
    }
  }
  if (file.language === "python") {
    for (const m of code.matchAll(PY_ANY_ESCAPE)) {
      pushFast(findings, { file, offset: m.index ?? 0, rule: "no-chained-or-any-cast", category: "structure", rung: "R0", severity: "error", message: `Python Any escape (${m[0].trim()}) disables static type checking.`, fix: "Use object, Protocol, TypeVar, or a validated model." });
    }
    for (const m of code.matchAll(PY_SWALLOWING_EXCEPT)) {
      pushFast(findings, { file, offset: m.index ?? 0, rule: "no-swallowing-catch", category: "structure", rung: "R0", severity: "error", message: "Python except-pass block silently swallows errors.", fix: "Rethrow or handle the specific expected exception explicitly." });
    }
    for (const m of code.matchAll(PY_PROD_ASSERT)) {
      pushFast(findings, { file, offset: m.index ?? 0, rule: "no-release-stripped-assert", category: "structure", rung: "R1", severity: "warn", message: "Bare Python assert in production code is stripped under python -O.", fix: "Raise an explicit InvariantViolationError so invariants stay active in release." });
    }
  }
  if (file.language === "rust") {
    for (const m of code.matchAll(RUST_SWALLOWING_ERR)) {
      pushFast(findings, { file, offset: m.index ?? 0, rule: "no-swallowing-catch", category: "structure", rung: "R0", severity: "error", message: "Empty Err(_) match arm silently swallows errors.", fix: "Propagate with '?' or handle the error variant explicitly." });
    }
  }
  if (file.language === "csharp" || file.language === "rust") {
    for (const m of code.matchAll(PROD_STRIPPED_ASSERT)) {
      pushFast(findings, { file, offset: m.index ?? 0, rule: "no-release-stripped-assert", category: "structure", rung: "R1", severity: "warn", message: "Debug assertion compiles out in Release builds.", fix: "Use an always-on production invariant check." });
    }
  }
}

function scanImmediateTest(file: ScannedFile, code: string, findings: Finding[]): void {
  for (const m of code.matchAll(TEST_SLEEP)) {
    pushFast(findings, { file, offset: m.index ?? 0, rule: "no-fixed-sleep", category: "cheat", rung: "R0", severity: "error", message: "Fixed sleep in test causes flakiness and slows CI.", fix: "Await an explicit signal, completion promise, or web-first locator." });
  }
  for (const m of code.matchAll(TEST_SKIP_ONLY)) {
    pushFast(findings, { file, offset: m.index ?? 0, rule: "test-discipline", category: "cheat", rung: "R0", severity: "error", message: "Skipped or focused test committed.", fix: "Fix or delete the test instead of skipping or focusing it." });
  }
  for (const m of code.matchAll(TEST_TAUTOLOGY)) {
    pushFast(findings, { file, offset: m.index ?? 0, rule: "weak-asserts-tautology", category: "test-smell", rung: "R0", severity: "error", message: "Tautological assertion cannot fail when behavior breaks.", fix: "Assert computed SUT output against an independent expected value." });
  }
  for (const m of code.matchAll(TEST_COND_EXPECT)) {
    pushFast(findings, { file, offset: m.index ?? 0, rule: "no-conditional-expect", category: "test-smell", rung: "R0", severity: "error", message: "Assertion inside conditional branch silently passes when skipped.", fix: "Split into explicit cases with unconditional assertions." });
  }
}

function makeSingleFileRepo(repoRoot: string, file: ScannedFile): DiscoveredRepo {
  const files: ScannedFile[] = [file];
  const cpAbs = path.join(repoRoot, ".verification", "chokepoints.json");
  if (fs.existsSync(cpAbs) && fs.statSync(cpAbs).isFile()) {
    try {
      const cpContent = fs.readFileSync(cpAbs, "utf8");
      files.push({ rel: ".verification/chokepoints.json", abs: cpAbs, isTest: false, isWorkflow: false, content: cpContent, lines: cpContent.split(/\r?\n/).length });
    } catch { void 0; }
  }
  return {
    root: repoRoot, files, allRelPaths: files.map((f) => f.rel),
    languages: file.language ? [file.language] : [], archetype: "library", observedArchetype: "library",
    scopeExclusions: [], signals: createEmptySignals(), ci: createEmptyCiSignals(),
  };
}

function scanCodeLanguageFile(file: ScannedFile, repoRoot: string, tier: CheckFileTier, maxLines: number): Finding[] {
  if (!file.language) return [];
  if (!repoRoot) throw new Error("repoRoot is required.");
  const rawFindings: Finding[] = [];
  if (!file.isStub) rawFindings.push(...lintNoComments(file.rel, file.content, file.language));
  if (!file.isTest && file.lines > maxLines) {
    rawFindings.push({
      id: `HF:max-file-lines:${file.rel}:1`, rule: "max-file-lines", category: "structure", rung: "R1", severity: "warn",
      file: file.rel, line: 1, message: `${file.rel} has ${file.lines} lines (limit: ${maxLines}).`,
      fix: "Split cohesive responsibilities into deeper modules with narrow interfaces.",
    });
  }
  const code = maskCode(file.content, file.language, !file.isTest);
  const ast = parseTsAst(file);
  if (file.isTest) {
    scanImmediateTest(file, code, rawFindings);
    rawFindings.push(...analyzeUniversalLandminesTest(file, code, ast));
    if (tier === "all") rawFindings.push(...analyzeTests(makeSingleFileRepo(repoRoot, file)).findings);
    return rawFindings;
  }
  scanImmediateProd(file, code, rawFindings);
  rawFindings.push(...lintImplicitStateMachinesInFile(file), ...analyzeUniversalBendLaws(file), ...analyzeUniversalAntiSlopProd(file, ast), ...analyzeTsAstGuards(file, ast));
  if (fs.existsSync(path.join(repoRoot, ".verification", "chokepoints.json"))) {
    rawFindings.push(...analyzeImmuneSystemGates(makeSingleFileRepo(repoRoot, file)));
  }
  if (tier === "all") {
    const singleRepo = makeSingleFileRepo(repoRoot, file);
    rawFindings.push(...analyzeStructure(singleRepo), ...analyzeRuntimeGuards(file), ...analyzeOssGuards(file), ...analyzeCveAndPostmortemGuards(file), ...analyzePerfHygiene(singleRepo));
  }
  return rawFindings;
}

export function scanSingleFile(filePath: string, options: CheckFileOptions = {}): CheckFileResult {
  const started = performance.now();
  const repoRoot = path.resolve(options.repoRoot ?? process.cwd());
  const abs = path.isAbsolute(filePath) ? path.resolve(filePath) : path.resolve(repoRoot, filePath);
  const rel = path.relative(repoRoot, abs).split(path.sep).join("/");
  const tier: CheckFileTier = options.tier ?? "immediate";
  const maxLines = options.maxLines ?? 500;
  const language = detectLanguageFast(rel);

  let content = options.content;
  if (content === undefined) {
    if (!fs.existsSync(abs) || !fs.statSync(abs).isFile()) throw new Error(`File not found: ${filePath}`);
    content = fs.readFileSync(abs, "utf8");
  }

  const isSql = /\.sql$/i.test(rel);
  const isShell = /\.(?:sh|bash)$/i.test(rel);
  const isWorkflow =
    ((rel.toLowerCase().startsWith(".github/workflows/") ||
      rel.toLowerCase().startsWith("ci/") ||
      rel.toLowerCase().startsWith(".azure-pipelines/") ||
      rel.toLowerCase().startsWith(".azuredevops/")) &&
      /\.ya?ml$/i.test(rel)) ||
    /^(?:\.gitlab-ci\.yml|\.?azure-pipelines\.ya?ml|\.circleci\/config\.yml|bitbucket-pipelines\.yml)$/i.test(rel);
  const sfc = extractSfcScript(rel, content);
  const effectiveLang = language ?? sfc?.language;
  const effectiveContent = sfc ? sfc.content : content;

  if (hasPathologicalNesting(content, effectiveLang ?? "typescript")) {
    return {
      file: rel, tier, language: language ?? null, elapsedMs: Number((performance.now() - started).toFixed(2)),
      findings: [{
        id: `HF:syntax-bomb:${rel}:1`, rule: "syntax-nesting-bomb", category: "cheat", rung: "R0", severity: "error", file: rel, line: 1,
        message: `${rel} exceeds safe syntax nesting depth (>128) or size (>2 MiB) — blocked fail-closed.`,
        fix: "Remove deeply nested expressions or oversized generated payloads.",
      }],
    };
  }
  if (!effectiveLang && !isSql && !isShell && !isWorkflow) {
    return { file: rel, tier, language: null, elapsedMs: Number((performance.now() - started).toFixed(2)), findings: [] };
  }

  const file: ScannedFile = {
    rel, abs, language: effectiveLang, isTest: pathHelpers.isTestFilePath(rel), isWorkflow,
    ...(pathHelpers.isDeclarationStub(rel) ? { isStub: true } : {}),
    content: effectiveContent, ...(sfc ? { rawContent: content } : {}),
    lines: content.length === 0 ? 0 : content.split(/\r?\n/).length,
  };

  const rawFindings: Finding[] = [];
  if (isWorkflow) {
    const singleRepo = makeSingleFileRepo(repoRoot, file);
    rawFindings.push(...auditCiWorkflows(singleRepo), ...analyzeImmuneSystemGates(singleRepo));
  } else if (isSql) {
    if (/(?:^|\/)migrations?\//i.test(file.rel)) rawFindings.push(...analyzeCveAndPostmortemGuards(file));
    rawFindings.push(...analyzeWave6TitansAGuards(file), ...analyzeWave7TitansBGuards(file));
  } else if (isShell) {
    rawFindings.push(...analyzeWave5AiFirstGuards(file), ...analyzeWave7TitansBGuards(file), ...analyzeBlackHoleReplayGuards(file), ...analyzeT3ProdGuards(file));
  } else if (effectiveLang) {
    rawFindings.push(...scanCodeLanguageFile(file, repoRoot, tier, maxLines));
  }

  const deduped = new Map<string, Finding>();
  for (const f of rawFindings) {
    const key = `${f.rule}:${f.file}:${f.line}`;
    if (!deduped.has(key)) deduped.set(key, f);
  }
  const unique = [...deduped.values()];
  const finalFindings = options.strict ? unique : applyRepoConfig(unique, loadRepoConfig(repoRoot)).findings;
  return { file: rel, tier, language, elapsedMs: Number((performance.now() - started).toFixed(2)), findings: finalFindings };
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
