import { Plugin, registerCoreServices, type Finding } from "@veristack/plugin";
import { auditManifestDowngrade } from "./anti-evasion.ts";
import { validateExecutableCommand } from "./command-audit.ts";
import { analyzeImmuneSystemGates } from "./immune-gates.ts";
import { auditRungCoverageFindings } from "./rung-gate.ts";

export { auditDiffAntiEvasion, auditManifestDowngrade, normalizeDiffMigrationPairs, scanUntrackedConfigCheats, type DiffLineEvent } from "./anti-evasion.ts";
export {
  extractToolHead,
  parseAndValidateCommandArgv,
  runArgvChain,
  sanitizeShellBlock,
  scrubChildEnv,
  validateExecutableCommand,
  type ArgvChainRunOptions,
} from "./command-audit.ts";
export { auditBunfigContent, auditRunnerConfigs, runGitClean, runGitCleanBuffer, VERIFICATION_TOOLS } from "./config-audit.ts";
export { analyzeImmuneSystemGates } from "./immune-gates.ts";
export { auditRungCoverageFindings, evaluateGreenfieldRungGate, hasBrownfieldRatchet, type RungGateOptions } from "./rung-gate.ts";
export { executeHookEvent, loadHookConfig } from "./runtime.ts";

function auditHooksDisabledFile(files: readonly { rel: string; content: string }[]): Finding[] {
  const hookCfgFile = files.find((f) => f.rel === ".verification/hooks.json");
  if (!hookCfgFile) return [];
  try {
    const parsedHook = JSON.parse(hookCfgFile.content) as Record<string, unknown>;
    if (parsedHook.enabled === false) {
      return [{
        id: "HOOK:disabled:.verification/hooks.json",
        rule: "hooks-disabled-in-config",
        category: "cheat",
        rung: "R0",
        severity: "error",
        file: ".verification/hooks.json",
        line: 1,
        message: ".verification/hooks.json sets enabled: false, disabling Veristack agent hooks.",
        fix: "Set enabled: true or run 'vstack hooks on' so per-edit and stop hooks remain active.",
      }];
    }
  } catch { void 0; }
  return [];
}

registerCoreServices({ validateCommand: validateExecutableCommand });

export const controlPlanePlugin = Plugin.define({
  id: "veristack.plugin.control-plane",
  guarded: true,
  setup(ctx) {
    registerCoreServices({ validateCommand: validateExecutableCommand });
    ctx.rung.transform((ed) => {
      ed.add({
        id: "veristack.control-plane.rung-guards",
        validateCommand: validateExecutableCommand,
        auditManifest: auditManifestDowngrade,
        auditRungCoverage: auditRungCoverageFindings,
      });
    });
    ctx.analyzer.transform((ed) => {
      ed.add({
        id: "veristack.control-plane.security",
        phase: "lint",
        run: (runCtx) => [
          ...auditHooksDisabledFile(runCtx.repo.files),
          ...analyzeImmuneSystemGates(runCtx.repo),
        ],
      });
    });
  },
});

export default controlPlanePlugin;
