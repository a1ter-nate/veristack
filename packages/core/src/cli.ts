import { registerCoreServices, type PluginOperation } from "@veristack/plugin";
import { getDefaultHostSync } from "./ladder.ts";
import { createPluginHost, type VeristackHostInstance } from "./plugin/host.ts";
import { buildRungStatuses } from "./rungs/coverage.ts";
import { loadRungManifest } from "./rungs/manifest.ts";
import { handleScanCli, handleVerifyAndRunRungCli } from "./rungs/scan-cli.ts";

const CLI_VALUE_FLAGS = new Set([
  "--base", "--max", "--max-lines", "--max-dirs", "--max-doc-lines", "--corroborate",
  "--provider", "--endpoint", "--model", "--image", "--command", "--input", "--test-cmd",
  "--max-time-exp", "--max-space-exp", "--ratchet", "--ratchet-base", "--config",
  "--disable", "--corpus", "--replay", "--baseline", "--tier", "--harness", "--targets",
  "--max-mutants", "--min-kill-rate", "--coverage", "--max-crap", "--plugin", "--disable-plugin",
]);

function extractPluginOperations(args: readonly string[]): { operations: PluginOperation[]; cleanArgs: string[] } {
  const operations: PluginOperation[] = [];
  const cleanArgs: string[] = [];
  for (let i = 0; i < args.length; i++) {
    const tok = args[i] ?? "";
    if (tok === "--plugin" && args[i + 1]) {
      operations.push({ type: "add", target: args[i + 1] ?? "" });
      i += 1;
      continue;
    }
    if (tok.startsWith("--plugin=")) {
      operations.push({ type: "add", target: tok.slice("--plugin=".length) });
      continue;
    }
    if (tok === "--disable-plugin" && args[i + 1]) {
      operations.push({ type: "remove", target: args[i + 1] ?? "" });
      i += 1;
      continue;
    }
    if (tok.startsWith("--disable-plugin=")) {
      operations.push({ type: "remove", target: tok.slice("--disable-plugin=".length) });
      continue;
    }
    cleanArgs.push(tok);
  }
  return { operations, cleanArgs };
}

function firstPositional(args: readonly string[]): string {
  for (let i = 0; i < args.length; i++) {
    const arg = args[i] ?? "";
    if (CLI_VALUE_FLAGS.has(arg)) { i += 1; continue; }
    if (!arg.startsWith("-")) return arg;
  }
  return ".";
}

function formatUsage(host: VeristackHostInstance): string {
  const lines = [
    "vstack — Deterministic Verification Stack (Tight-Core + Dogfooded Plugins)",
    "",
    "Global plugin flags:",
    "  --plugin <path|pkg>        Load an external Veristack plugin package or file",
    "  --disable-plugin <id|*>    Disable a non-guarded plugin (guarded control-plane plugins remain active)",
    "",
    "Core Commands:",
    "  vstack scan [dir] [--json | --md] [--strict] [--ratchet <file>] [--plugin <path>] [--disable-plugin <id>]",
    "  vstack verify [dir] [--strict] [--json | --md]",
    "  vstack run-rung <R0..R8|all> [dir] [--json]",
    "  vstack plugins [list] [--plugin <path>] [--disable-plugin <id>] [--json]",
    "",
    "Plugin Commands:",
  ];
  for (const cmd of host.registries.commands()) {
    lines.push(`  ${cmd.usage ?? `vstack ${cmd.name}`}`);
  }
  return lines.join("\n");
}

function handlePluginsCommand(host: VeristackHostInstance, asJson: boolean): number {
  const entries = host.list();
  if (asJson) {
    console.log(JSON.stringify({ count: entries.length, plugins: entries }, null, 2));
    return 0;
  }
  console.log(`Veristack Plugins (${entries.length}):`);
  for (const p of entries) {
    const guardTag = p.guarded ? " [guarded]" : "";
    const errTag = p.error ? ` — ${p.error}` : "";
    console.log(`  - ${p.id} (${p.status}${guardTag}) [${typeof p.source === "string" ? p.source : p.source.type}]${errTag}`);
  }
  return 0;
}

export async function runCli(argv: readonly string[]): Promise<number> {
  const { operations, cleanArgs } = extractPluginOperations(argv);
  const cmd = cleanArgs[0];
  const rest = cleanArgs.slice(1);
  const target = firstPositional(rest);
  const asJson = rest.includes("--json");
  const asMd = rest.includes("--md");

  if (rest.includes("--strict") && operations.some((op) => op.type === "remove")) {
    console.error("vstack --strict forbids --disable-plugin.");
    return 1;
  }

  const host =
    operations.length === 0
      ? getDefaultHostSync()
      : await createPluginHost({ repoDir: target, includeBuiltins: true, operations });

  registerCoreServices({
    discoverRepo: (p) => host.discover(p),
    scanRepo: (p, opts) => host.scanSync(p, opts as Record<string, unknown> | undefined),
    buildRungStatuses,
    loadRungManifest: (root) => loadRungManifest(root),
  });

  try {
    if (!cmd || cmd === "-h" || cmd === "--help") {
      console.log(formatUsage(host));
      return 0;
    }
    if (cmd === "plugins") return handlePluginsCommand(host, asJson);
    if (cmd === "scan") return await handleScanCli(host, rest, target, { asJson, asMd });

    const verifyCode = await handleVerifyAndRunRungCli(host, cmd, rest, target);
    if (verifyCode !== null) return verifyCode;

    const pluginCmd = host.registries.commands().find((c) => c.name === cmd);
    if (pluginCmd && typeof pluginCmd.run === "function") {
      return await pluginCmd.run({ cmd, rest, target, asJson, asMd, host });
    }

    console.error(`Unknown command: ${cmd}\n`);
    console.error(formatUsage(host));
    return 2;
  } finally {
    if (operations.length > 0) await host.dispose();
  }
}
