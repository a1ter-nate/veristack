import path from "node:path";
import { lineOf, maskCode, type DiscoveredRepo, type Finding, type LanguagePluginSpec, type ScannedFile } from "@veristack/plugin";
import { parseTsAst } from "@veristack/plugin-lang-typescript";
import { analyzeOracleAndInstructions } from "./oracle-audit.ts";
import { analyzeUniversalAntiSlopProd } from "./oxc-antislop-landmines.ts";
import { analyzeUniversalBendLaws } from "./universal-laws.ts";

const WIDE_DIR_LIMIT = 15;
const WARN_FILE_LINES = 500;
const HARD_FILE_LINES = 2000;
const MAX_AGENTS_LINES = 200;

const GENERATED_PATH = /(?:^|\/)(?:generated|generated-clients?|codegen|__snapshots__)\/|\.(?:gen|generated)\.[cm]?[jt]sx?$/i;
const GENERATED_HEADER = /(?:@generated|auto-generated|do\s+not\s+edit|generated\s+by\b)/i;
const UNBOUNDED_LOOP = /\bwhile\s*\(\s*true\s*\)|\bwhile\s+True\s*:|\bloop\s*\{/g;
const CATCH_OPEN = /\bcatch\s*(?:\([^)]*\))?\s*\{/g;
const SHAM_SUCCESS_RETURN = /\breturn\s*(?:true|(?:(?:Results\.|TypedResults\.)?Ok|new\s+OkObjectResult|new\s+JsonResult|NextResponse\.json|Response\.json|res\.(?:status\s*\(\s*200\s*\)\.)?json)\s*\(\s*(?:new\s*)?\{[^}]{0,160}\b(?:accepted|ok|success)\s*[:=]\s*true\b[^}]*\}\s*\)|\{[^}]{0,160}\b(?:accepted|ok|success)\s*:\s*true\b[^}]*\})\s*;|(?:const|let|var)\s+([A-Za-z_$]\w*)\s*=\s*\{[^}]{0,160}\b(?:accepted|ok|success)\s*:\s*true\b[^}]*\}[\s\S]{0,120}\breturn\s+\1\b/i;
const CATCHALL_SUCCESS_STUB = /\bdefault\s*:\s*\{?\s*return\s*(?:(?:Results\.|TypedResults\.)?Ok\s*\(\s*new\s*|new\s+OkObjectResult\s*\(\s*new\s*|NextResponse\.json\s*\(|Response\.json\s*\(|res\.(?:status\s*\(\s*200\s*\)\.)?json\s*\()?\{[^}]{0,120}\b(?:accepted|ok|success)\s*[:=]\s*true\b/g;

function extractBalancedBraceBody(masked: string, raw: string, openBraceIdx: number): string {
  let depth = 0;
  for (let i = openBraceIdx; i < masked.length && i < openBraceIdx + 1200; i++) {
    if (masked[i] === "{") depth += 1;
    else if (masked[i] === "}" && --depth === 0) return raw.slice(openBraceIdx, i + 1);
  }
  return "";
}

function scanCommonProdGuards(file: ScannedFile, findings: Finding[]): void {
  if (!file.language || file.isTest || file.isStub) return;
  const raw = file.content;
  const masked = maskCode(raw, file.language, true);
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
  if (file.language === "typescript" || file.language === "javascript" || file.language === "csharp") {
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
  const ast = parseTsAst(file);
  findings.push(...analyzeUniversalBendLaws(file), ...analyzeUniversalAntiSlopProd(file, ast));
}

function scanDirectoryBudgets(
  dirMembers: ReadonlyMap<string, Set<string>>,
  dirSourceFiles: ReadonlyMap<string, string[]>,
  findings: Finding[],
): void {
  if (dirMembers.size === 0 && dirSourceFiles.size === 0) return;
  for (const [dir, members] of dirMembers.entries()) {
    if (dir === "." || dir.includes("fixtures") || GENERATED_PATH.test(`${dir}/`)) continue;
    if (members.size > WIDE_DIR_LIMIT) {
      findings.push({ id: `ST:wide-dir:${dir}`, rule: "wide-directory", category: "structure", rung: "R1", severity: "warn", file: dir, line: 1, message: `Directory ${dir}/ holds ${members.size} entries (budget: <= ${WIDE_DIR_LIMIT}).`, fix: "Group related files into feature subdirectories so agents read rather than search listings." });
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
      const dirBase = path.posix.basename(dir).toLowerCase();
      if (dirBase === prefix.toLowerCase() || dirBase === `${prefix.toLowerCase()}s` || `${dirBase}s` === prefix.toLowerCase()) continue;
      if (list.length >= 3) {
        findings.push({ id: `ST:prefix-cluster:${dir}:${prefix}`, rule: "no-prefix-cluster", category: "structure", rung: "R1", severity: "warn", file: dir, line: 1, message: `${list.length} sibling modules in ${dir}/ share prefix "${prefix}-" (${list.slice(0, 4).join(", ")}).`, fix: `Group them into a ${dir === "." ? prefix : `${dir}/${prefix}`}/ feature folder with a narrow entry point.` });
      }
    }
  }
}

export function analyzeStructure(
  repo: DiscoveredRepo,
  activeLanguages: readonly LanguagePluginSpec[] = [],
): Finding[] {
  if (!repo.root) throw new Error("Repo root is required.");
  const findings: Finding[] = [];
  if (repo.files.length === 0 && repo.allRelPaths.length === 0) return findings;
  const langById = new Map<string, LanguagePluginSpec>(activeLanguages.map((l) => [l.id, l]));
  const dirMembers = new Map<string, Set<string>>();
  const dirSourceFiles = new Map<string, string[]>();

  for (const rel of repo.allRelPaths) {
    const dir = path.posix.dirname(rel);
    const members = dirMembers.get(dir) ?? new Set<string>();
    members.add(path.posix.basename(rel));
    dirMembers.set(dir, members);
  }

  for (const file of repo.files) {
    const isGenerated = GENERATED_PATH.test(file.rel) && GENERATED_HEADER.test(file.content.slice(0, 600));
    const isStub = Boolean(file.isStub) || /\.d\.[cm]?ts$|\.pyi$/i.test(file.rel);
    if (file.language && !file.isTest && !isGenerated) {
      const dir = path.posix.dirname(file.rel);
      const list = dirSourceFiles.get(dir) ?? [];
      list.push(path.posix.basename(file.rel));
      dirSourceFiles.set(dir, list);
    }
    if (file.language && !file.isTest && !isGenerated && !isStub && file.lines > WARN_FILE_LINES) {
      const isHard = file.lines > HARD_FILE_LINES;
      findings.push({ id: `ST:long-file:${file.rel}`, rule: isHard ? "long-file" : "max-file-lines", category: "structure", rung: "R1", severity: isHard ? "error" : "warn", file: file.rel, line: 1, message: `${file.rel} has ${file.lines} lines (limit: ${isHard ? HARD_FILE_LINES : WARN_FILE_LINES}).`, fix: "Split cohesive responsibilities into deeper modules with narrow interfaces; avoid mechanical splits." });
    }
    if (file.language && !isGenerated && !isStub) {
      const langSpec = langById.get(file.language);
      if (langSpec?.scanStructure) findings.push(...langSpec.scanStructure(file));
      scanCommonProdGuards(file, findings);
    }
    const baseLower = path.posix.basename(file.rel).toLowerCase();
    if ((baseLower === "agents.md" || baseLower === "claude.md") && file.lines > MAX_AGENTS_LINES) {
      findings.push({ id: `AH:long-instructions:${file.rel}`, rule: "agents-md-size", category: "oracle-lock", rung: "R0", severity: "warn", file: file.rel, line: 1, message: `${file.rel} is ${file.lines} lines (budget: <= ${MAX_AGENTS_LINES}).`, fix: "Promote mechanical rules to linters/hooks and move deep reference material into on-demand skill references." });
    }
  }
  scanDirectoryBudgets(dirMembers, dirSourceFiles, findings);
  findings.push(...analyzeOracleAndInstructions(repo));
  return findings;
}
