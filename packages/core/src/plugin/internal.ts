import type { VeristackPlugin } from "@veristack/plugin";
import { agentDocsPlugin } from "@veristack/plugin-agent-docs";
import { antiSlopPlugin } from "@veristack/plugin-anti-slop";
import { canaryPlugin } from "@veristack/plugin-canary";
import { ciAuditorPlugin } from "@veristack/plugin-ci-auditor";
import { circuitsPlugin } from "@veristack/plugin-circuits";
import { controlPlanePlugin } from "@veristack/plugin-control-plane";
import { effectV4Plugin } from "@veristack/plugin-effect-v4";
import { harnessesPlugin } from "@veristack/plugin-harnesses";
import { langCsharpPlugin } from "@veristack/plugin-lang-csharp";
import { langGoPlugin } from "@veristack/plugin-lang-go";
import { langPythonPlugin } from "@veristack/plugin-lang-python";
import { langRustPlugin } from "@veristack/plugin-lang-rust";
import { langTypescriptPlugin } from "@veristack/plugin-lang-typescript";
import { lawsFormalPlugin } from "@veristack/plugin-laws-formal";
import { reviewBriefPlugin } from "@veristack/plugin-review-brief";
import { stateMachinesPlugin } from "@veristack/plugin-state-machines";
import { tigerstylePlugin } from "@veristack/plugin-tigerstyle";
import { zeroDefectPlugin } from "@veristack/plugin-zero-defect";

export const pre: readonly VeristackPlugin[] = [
  controlPlanePlugin,
  canaryPlugin,
  langTypescriptPlugin,
  langCsharpPlugin,
  langRustPlugin,
  langPythonPlugin,
  langGoPlugin,
  ciAuditorPlugin,
  harnessesPlugin,
  circuitsPlugin,
];

export const post: readonly VeristackPlugin[] = [
  antiSlopPlugin,
  stateMachinesPlugin,
  tigerstylePlugin,
  effectV4Plugin,
  zeroDefectPlugin,
  agentDocsPlugin,
  reviewBriefPlugin,
  lawsFormalPlugin,
];

export const guarded: ReadonlySet<string> = new Set([
  controlPlanePlugin.id,
  canaryPlugin.id,
]);

export const builtinPluginManifest = Object.freeze({
  pre,
  post,
  guarded,
});
