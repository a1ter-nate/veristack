import { pathHelpers, Plugin, type DiscoveredRepo, type Finding } from "@veristack/plugin";
import { analyzeBlackHoleReplayGuards } from "./blackhole-replay-guards.ts";
import { analyzeBlackHoleArchGates } from "./cross-file-graph.ts";
import { analyzeDeviantInvariants } from "./deviant-invariants.ts";
import { analyzeInvariantGuards } from "./invariant-loss.ts";
import { analyzeLinearObligations } from "./linear-obligations.ts";
import { extractSfcScript } from "./sfc.ts";
import { scanTsJsStructure } from "./structure-ts.ts";
import { analyzeT3ProdGuards } from "./t3-immune-rules.ts";
import { analyzeTsAstGuards, parseTsAst } from "./ts-ast.ts";
import { analyzeWave5AiFirstGuards } from "./wave5-ai-first.ts";
import { analyzeWave6TitansAGuards } from "./wave6-titans-a.ts";
import { analyzeWave7TitansBGuards } from "./wave7-titans-b.ts";

export { analyzeBlackHoleReplayGuards } from "./blackhole-replay-guards.ts";
export { analyzeBlackHoleArchGates } from "./cross-file-graph.ts";
export { analyzeDeviantInvariants } from "./deviant-invariants.ts";
export {
  analyzeInvariantGuards,
  auditDiffInvariantLoss,
  auditTsAstPredicateDrop,
  buildSyntheticRevertEvents,
} from "./invariant-loss.ts";
export { analyzeLinearObligations } from "./linear-obligations.ts";
export { extractSfcScript, scanSfcScriptSpans } from "./sfc.ts";
export { scanTsJsStructure } from "./structure-ts.ts";
export { analyzeT3ProdGuards, analyzeT3TestGuards } from "./t3-immune-rules.ts";
export {
  analyzeTsAstGuards,
  getMemberChain,
  hasPathologicalNesting,
  isAstNode,
  parseTsAst,
  walkAst,
  type AstNode,
} from "./ts-ast.ts";
export { analyzeWave5AiFirstGuards } from "./wave5-ai-first.ts";
export { analyzeWave6TitansAGuards } from "./wave6-titans-a.ts";
export { analyzeWave7TitansBGuards } from "./wave7-titans-b.ts";

const GENERATED_PATH = /(?:^|\/)(?:generated|generated-clients?|codegen|__snapshots__)\/|\.(?:gen|generated)\.[cm]?[jt]sx?$/i;
const GENERATED_HEADER = /(?:@generated|auto-generated|do\s+not\s+edit|generated\s+by\b)/i;

function runTsAstAndWaveAnalyzers(repo: DiscoveredRepo): Finding[] {
  if (!repo.root) throw new Error("DiscoveredRepo.root is required.");
  const findings: Finding[] = [];
  for (const file of repo.files) {
    if (file.rel.endsWith(".sql")) {
      findings.push(...analyzeWave6TitansAGuards(file), ...analyzeWave7TitansBGuards(file));
      continue;
    }
    if (/\.(?:sh|bash)$/i.test(file.rel)) {
      findings.push(
        ...analyzeWave5AiFirstGuards(file),
        ...analyzeWave7TitansBGuards(file),
        ...analyzeBlackHoleReplayGuards(file),
        ...analyzeT3ProdGuards(file),
      );
      continue;
    }
    const isStub = Boolean(file.isStub) || pathHelpers.isDeclarationStub(file.rel);
    if (!file.language || file.isTest || isStub) continue;
    if (GENERATED_PATH.test(file.rel) && GENERATED_HEADER.test(file.content.slice(0, 600))) continue;
    const ast = parseTsAst(file);
    findings.push(
      ...analyzeWave5AiFirstGuards(file),
      ...analyzeWave6TitansAGuards(file),
      ...analyzeWave7TitansBGuards(file),
      ...analyzeTsAstGuards(file, ast),
      ...analyzeLinearObligations(file, ast),
      ...analyzeBlackHoleReplayGuards(file, ast),
      ...analyzeT3ProdGuards(file, ast),
      ...analyzeInvariantGuards(file),
    );
  }
  findings.push(...analyzeBlackHoleArchGates(repo), ...analyzeDeviantInvariants(repo));
  return findings;
}

export const langTypescriptPlugin = Plugin.define({
  id: "veristack.plugin.lang-typescript",
  setup(ctx) {
    ctx.language.transform((ed) => {
      ed.add({
        id: "typescript",
        extensions: [".ts", ".tsx", ".mts", ".cts"],
        sfcExtensions: [".vue", ".svelte", ".astro"],
        extractEmbeddedScript: extractSfcScript,
        scanStructure: scanTsJsStructure,
      });
      ed.add({
        id: "javascript",
        extensions: [".js", ".jsx", ".mjs", ".cjs"],
        scanStructure: scanTsJsStructure,
      });
    });
    ctx.analyzer.transform((ed) => {
      ed.add({
        id: "veristack.typescript.ast-and-waves",
        phase: "lint",
        run: (runCtx) => runTsAstAndWaveAnalyzers(runCtx.repo),
      });
    });
  },
});

export default langTypescriptPlugin;
