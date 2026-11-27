import { spawnSync, type SpawnSyncReturns } from "node:child_process";
import type { CiExecutionSignals, ToolSignals } from "./types.ts";

const CLEAN_GIT_FLAGS = [
  "-c",
  "core.attributesFile=/dev/null",
  "-c",
  "diff.noprefix=false",
  "-c",
  "diff.mnemonicPrefix=false",
  "-c",
  "core.quotepath=false",
];

function cleanGitEnv(): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = {};
  for (const [k, v] of Object.entries(process.env)) {
    if (v !== undefined && !k.startsWith("GIT_")) env[k] = v;
  }
  return env;
}

export function runGitClean(
  repoRoot: string,
  args: readonly string[],
  options: { maxBuffer?: number; timeout?: number } = {},
): SpawnSyncReturns<string> {
  return spawnSync("git", ["-C", repoRoot, ...CLEAN_GIT_FLAGS, ...args], {
    encoding: "utf8",
    env: cleanGitEnv(),
    maxBuffer: options.maxBuffer ?? 16 * 1024 * 1024,
    timeout: options.timeout,
  });
}

export function runGitCleanBuffer(
  repoRoot: string,
  args: readonly string[],
  options: { maxBuffer?: number; timeout?: number } = {},
): SpawnSyncReturns<Buffer> {
  return spawnSync("git", ["-C", repoRoot, ...CLEAN_GIT_FLAGS, ...args], {
    env: cleanGitEnv(),
    maxBuffer: options.maxBuffer ?? 32 * 1024 * 1024,
    timeout: options.timeout,
  });
}

export function stripLiteralsAndComments(content: string): string {
  return content
    .replace(/"""[\s\S]*?"""|'''[\s\S]*?'''/g, '""')
    .replace(/\/\*[\s\S]*?\*\//g, " ")
    .replace(/(^|[^:\\])\/\/[^\n]*/g, "$1 ")
    .replace(/(^|\s)#[^\n]*/g, "$1 ")
    .replace(/\/(?:\\.|[^/\\\n])+\/[gimsuy]*/g, " ")
    .replace(/"(?:\\.|[^"\\])*"/g, '""')
    .replace(/'(?:\\.|[^'\\])*'/g, "''")
    .replace(/`(?:\\.|[^`\\])*`/g, "``");
}

export function isHostRepoFile(rel: string): boolean {
  const norm = rel.replace(/\\/g, "/");
  if (norm === "docs/CODEOWNERS") return true;
  return !/^(?:templates|examples|samples|demo|demos|snippets|docs_src|benchmarks?|perf-measures|fuzz|docs|web\/docs|website|runtime-tests|default\/(?:agents|games|chromium))\//i.test(norm);
}

export function createEmptySignals(): ToolSignals {
  return {
    hasFormatter: false, hasLinter: false, hasOxlint: false, hasAntiSlop: false, hasLandmines: false,
    hasGoInternal: false, hasDeslopPlease: false, hasDesloppify: false, hasStrictTypes: false, hasTsgo: false,
    hasKnipOrDeadCode: false, hasJscpd: false, hasArchFitness: false, hasPreCommitHook: false, hasCodeowners: false,
    hasReviewMd: false, hasAgentsMd: false, hasPbt: false, hasMbt: false, hasContractTool: false,
    hasComponentUiTool: false, hasMsw: false, hasMswStrict: false, hasTestcontainersOrRealDb: false,
    hasMigrationTest: false, hasBusDlqTest: false, hasDst: false, hasDryRun: false, hasMutationTool: false,
    hasFormalTool: false, hasFuzzTool: false, hasBombadil: false, hasVisualTool: false, hasPerfOrLoadTool: false,
    hasE2eTool: false, hasProdTelemetryOrCanary: false, hasDiffSelection: false,
  };
}

export function createEmptyCiSignals(): CiExecutionSignals {
  return {
    hasCiWorkflows: false, workflowFiles: [], runsFormatterOrLint: false, runsTypeOrStructureCheck: false,
    runsUnitTests: false, runsBoundaryOrMbtTests: false, runsIntegrationOrDbTests: false, runsMutationOrFormal: false,
    runsPerfOrBench: false, runsE2eTests: false, runsProdVerification: false,
  };
}
