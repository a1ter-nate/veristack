import fs from "node:fs";
import { Plugin, type CircuitId, type CommandRunContext, type System1ModelAnswer, type System1ProviderId } from "@veristack/plugin";
import { createSystem1Engine, formatCircuitReport, listDefaultCircuits, runRepoCircuit } from "./circuits.ts";
import { buildSystem1Packet, corroborateSystem1Batch } from "./system1-classifier.ts";
import { runSystem1Provider } from "./system1-providers.ts";

export {
  instructionLintPromoterCircuit,
  perfArchitectureAdvisorCircuit,
  prRiskRouterCircuit,
  testTriageCircuit,
  type InstructionRuleInput,
  type PerfAdvisorInput,
  type PrRiskInput,
  type TestTriageInput,
} from "./catalog.ts";
export { createSystem1Engine, formatCircuitReport, listDefaultCircuits, runRepoCircuit } from "./circuits.ts";
export {
  checkCrossSurfaceParity,
  checkMetamorphicRelation,
  createCorpusSeedStore,
  type CorpusSeedEntry,
  type CrossSurfaceParityResult,
  type MetamorphicCheckResult,
  type MetamorphicRelationKind,
} from "./metamorphic.ts";
export { resolveThreeBandDecision, runCircuit, type CircuitDefinition, type System1DecisionEngine } from "./engine.ts";
export { buildSystem1Packet, corroborateSystem1Batch } from "./system1-classifier.ts";
export { runSystem1Provider, type System1ProviderOptions } from "./system1-providers.ts";

const BUILTIN_PROVIDERS: readonly { id: System1ProviderId; label: string }[] = [
  { id: "laya", label: "Laya" },
  { id: "jev", label: "JEV" },
  { id: "local", label: "Local" },
  { id: "command", label: "Command" },
  { id: "fixture", label: "Fixture" },
];

function parseFlagValue(args: readonly string[], flag: string): string | undefined {
  for (let i = 0; i < args.length; i++) {
    const a = args[i] ?? "";
    if (a === flag) return args[i + 1];
    if (a.startsWith(`${flag}=`)) return a.slice(flag.length + 1);
  }
  return undefined;
}

function firstPositional(args: readonly string[]): string {
  const valueFlags = new Set(["--provider", "--endpoint", "--model", "--image", "--command", "--base", "--max"]);
  for (let i = 0; i < args.length; i++) {
    const a = args[i] ?? "";
    if (valueFlags.has(a)) { i += 1; continue; }
    if (!a.startsWith("-")) return a;
  }
  return ".";
}

function readHostRegistryIds(host: unknown, domain: "circuits" | "providers"): string[] {
  if (!host || typeof host !== "object") return [];
  const regs = (host as { registries?: Record<string, () => readonly { id: string }[]> }).registries;
  const getter = regs?.[domain];
  return typeof getter === "function" ? getter().map((x) => x.id) : [];
}

function validateProvider(raw: string | undefined, host: unknown): System1ProviderId | undefined {
  if (!raw) return undefined;
  const known = readHostRegistryIds(host, "providers");
  const allowed = known.length > 0 ? known : BUILTIN_PROVIDERS.map((p) => p.id);
  if (allowed.includes(raw)) return raw;
  throw new Error(`Unsupported --provider "${raw}". Expected one of: ${allowed.join(", ")}.`);
}

function validateCircuit(raw: string | undefined, host: unknown): CircuitId {
  const known = readHostRegistryIds(host, "circuits");
  const allowed = known.length > 0 ? known : listDefaultCircuits().map((c) => c.id);
  if (raw && allowed.includes(raw)) return raw;
  throw new Error(`Unsupported circuit "${raw ?? ""}". Expected one of: ${allowed.join(", ")}.`);
}

async function runClassifyCommand(ctx: CommandRunContext): Promise<number> {
  const maxRaw = parseFlagValue(ctx.rest, "--max");
  let packet = buildSystem1Packet(ctx.target, { maxCandidates: maxRaw ? Number(maxRaw) : 30 });
  const provider = validateProvider(parseFlagValue(ctx.rest, "--provider"), ctx.host);
  const corroboratePath = parseFlagValue(ctx.rest, "--corroborate");
  if (provider) {
    const answers = await runSystem1Provider(packet.requests, {
      provider,
      endpoint: parseFlagValue(ctx.rest, "--endpoint"),
      model: parseFlagValue(ctx.rest, "--model"),
      image: parseFlagValue(ctx.rest, "--image"),
      command: parseFlagValue(ctx.rest, "--command"),
    });
    packet = { ...corroborateSystem1Batch(packet, answers), provider };
  } else if (corroboratePath) {
    packet = corroborateSystem1Batch(packet, JSON.parse(fs.readFileSync(corroboratePath, "utf8")) as System1ModelAnswer[]);
  }
  if (ctx.rest.includes("--emit-requests")) {
    console.log(JSON.stringify({ rubricVersion: packet.rubricVersion, rubricHash: packet.rubricHash, requests: packet.requests }, null, 2));
    return 0;
  }
  console.log(JSON.stringify(packet, null, 2));
  return 0;
}

async function runCircuitCommand(ctx: CommandRunContext): Promise<number> {
  if (!ctx) throw new Error("Command context is required.");
  const sub = ctx.rest[0];
  if (sub === "list") {
    const circuits = listDefaultCircuits();
    if (ctx.asJson) console.log(JSON.stringify({ circuits }, null, 2));
    else for (const c of circuits) console.log(`${c.id} (v${c.version}) — ${c.title}\n  ${c.description}`);
    return 0;
  }
  if (sub === "run") {
    const circuitId = validateCircuit(ctx.rest[1], ctx.host);
    const circuitArgs = ctx.rest.slice(2);
    const provider = validateProvider(parseFlagValue(circuitArgs, "--provider"), ctx.host) ?? "fixture";
    const engine = createSystem1Engine({
      provider,
      endpoint: parseFlagValue(circuitArgs, "--endpoint"),
      model: parseFlagValue(circuitArgs, "--model"),
      image: parseFlagValue(circuitArgs, "--image"),
      command: parseFlagValue(circuitArgs, "--command"),
    });
    const maxRaw = parseFlagValue(circuitArgs, "--max");
    const report = await runRepoCircuit(circuitId, firstPositional(circuitArgs), engine, {
      baseRef: parseFlagValue(circuitArgs, "--base"),
      maxCandidates: maxRaw ? Number(maxRaw) : undefined,
    });
    console.log(ctx.asJson ? JSON.stringify(report, null, 2) : formatCircuitReport(report));
    return 0;
  }
  console.error(`Unknown circuit subcommand: ${sub ?? ""}`);
  return 2;
}

export const circuitsPlugin = Plugin.define({
  id: "veristack.plugin.circuits",
  setup(ctx) {
    ctx.circuit.transform((ed) => {
      for (const meta of listDefaultCircuits()) ed.add({ ...meta });
    });
    ctx.provider.transform((ed) => {
      for (const p of BUILTIN_PROVIDERS) ed.add({ ...p });
    });
    ctx.command.transform((ed) => {
      ed.add({
        id: "veristack.cmd.classify",
        name: "classify",
        usage: "vstack classify [dir] [--max <n>] [--emit-requests] [--provider <id>] [--json]",
        run: runClassifyCommand,
      });
      ed.add({
        id: "veristack.cmd.circuit",
        name: "circuit",
        usage: "vstack circuit <list|run> ...",
        run: runCircuitCommand,
      });
    });
  },
});

export default circuitsPlugin;
