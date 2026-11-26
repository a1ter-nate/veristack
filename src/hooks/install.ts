import fs from "node:fs";
import path from "node:path";
import { type HookHarness, type HookProjectConfig, loadHookConfig } from "./runtime.ts";

export type HooksAdminAction = "on" | "off" | "status" | "reset";

export interface HooksAdminResult {
  action: HooksAdminAction;
  repoRoot: string;
  configPath: string;
  enabled: boolean;
  harnesses: HookHarness[];
  touchedManifests: string[];
  summary: string;
}

const ALL_HARNESSES: readonly HookHarness[] = ["claude", "codex", "cursor", "copilot", "grok"];

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

function readJsonObj(filePath: string): Record<string, unknown> {
  if (!fs.existsSync(filePath)) return {};
  try {
    const parsed: unknown = JSON.parse(fs.readFileSync(filePath, "utf8"));
    return isRecord(parsed) ? parsed : {};
  } catch {
    return {};
  }
}

function writeJsonObj(filePath: string, data: object): void {
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.writeFileSync(filePath, `${JSON.stringify(data, null, 2)}\n`, "utf8");
}

const HOOK_CMD_PATTERNS: Record<"any" | "pre-edit" | "post-edit" | "stop", readonly [RegExp, RegExp]> = {
  any: [
    /^(?:npx\s+(?:--no-install\s+)?|bunx\s+|bun\s+\S+\s+|node\s+\S+\s+)?(?:vstack|veristack)\s+hook\s+(?:pre-edit|post-edit|stop)(?:\s+--[a-z-]+(?:\s+[a-z0-9_-]+)?)*$/,
    /^(?:bun\s+src\/cli\.ts|node\s+bin\/vstack\.mjs)\s+hook\s+(?:pre-edit|post-edit|stop)(?:\s+--[a-z-]+(?:\s+[a-z0-9_-]+)?)*$/,
  ],
  "pre-edit": [
    /^(?:npx\s+(?:--no-install\s+)?|bunx\s+|bun\s+\S+\s+|node\s+\S+\s+)?(?:vstack|veristack)\s+hook\s+pre-edit(?:\s+--[a-z-]+(?:\s+[a-z0-9_-]+)?)*$/,
    /^(?:bun\s+src\/cli\.ts|node\s+bin\/vstack\.mjs)\s+hook\s+pre-edit(?:\s+--[a-z-]+(?:\s+[a-z0-9_-]+)?)*$/,
  ],
  "post-edit": [
    /^(?:npx\s+(?:--no-install\s+)?|bunx\s+|bun\s+\S+\s+|node\s+\S+\s+)?(?:vstack|veristack)\s+hook\s+post-edit(?:\s+--[a-z-]+(?:\s+[a-z0-9_-]+)?)*$/,
    /^(?:bun\s+src\/cli\.ts|node\s+bin\/vstack\.mjs)\s+hook\s+post-edit(?:\s+--[a-z-]+(?:\s+[a-z0-9_-]+)?)*$/,
  ],
  stop: [
    /^(?:npx\s+(?:--no-install\s+)?|bunx\s+|bun\s+\S+\s+|node\s+\S+\s+)?(?:vstack|veristack)\s+hook\s+stop(?:\s+--[a-z-]+(?:\s+[a-z0-9_-]+)?)*$/,
    /^(?:bun\s+src\/cli\.ts|node\s+bin\/vstack\.mjs)\s+hook\s+stop(?:\s+--[a-z-]+(?:\s+[a-z0-9_-]+)?)*$/,
  ],
};

function isRealVstackHookCommand(cmd: unknown, expectedEvent?: "pre-edit" | "post-edit" | "stop"): boolean {
  if (typeof cmd !== "string") return false;
  const trimmed = cmd.trim();
  if (/[;|>&`\n\r]|\|\|/.test(trimmed)) return false;
  const [re1, re2] = HOOK_CMD_PATTERNS[expectedEvent ?? "any"];
  return re1.test(trimmed) || re2.test(trimmed);
}

function matcherCoversEdits(matcher: unknown): boolean {
  if (typeof matcher !== "string" || !matcher.trim()) return false;
  try {
    const re = new RegExp(matcher);
    return re.test("Edit") || re.test("Write");
  } catch {
    return false;
  }
}

function containsVstackCommand(entry: unknown, expectedEvent?: "pre-edit" | "post-edit" | "stop", requireEditMatcher = false): boolean {
  if (!isRecord(entry)) return false;
  if (requireEditMatcher && !matcherCoversEdits(entry.matcher)) return false;
  if (isRealVstackHookCommand(entry.command, expectedEvent)) return true;
  if (Array.isArray(entry.hooks)) {
    return entry.hooks.some((h) => isRecord(h) && isRealVstackHookCommand(h.command, expectedEvent));
  }
  return false;
}

function mergeHookBucket(existing: unknown, newEntry: Record<string, unknown>): Record<string, unknown>[] {
  const list = Array.isArray(existing) ? existing.filter((item) => !containsVstackCommand(item)) : [];
  return [...(list as Record<string, unknown>[]), newEntry];
}

function stripHookBucket(existing: unknown): unknown[] {
  if (!Array.isArray(existing)) return [];
  return existing.filter((item) => !containsVstackCommand(item));
}

function manifestPathFor(repoRoot: string, harness: HookHarness): string {
  switch (harness) {
    case "claude":
      return path.join(repoRoot, ".claude", "settings.local.json");
    case "codex":
      return path.join(repoRoot, ".codex", "hooks.json");
    case "cursor":
      return path.join(repoRoot, ".cursor", "hooks.json");
    case "copilot":
      return path.join(repoRoot, ".github", "hooks", "veristack.json");
    case "grok":
      return path.join(repoRoot, ".grok", "hooks", "veristack.json");
  }
}

function installHarnessManifest(repoRoot: string, harness: HookHarness, cmdPrefix: string): string {
  const filePath = manifestPathFor(repoRoot, harness);
  const rel = path.relative(repoRoot, filePath).split(path.sep).join("/");
  const doc = readJsonObj(filePath);
  const hooks = isRecord(doc.hooks) ? { ...doc.hooks } : {};

  if (harness === "cursor") {
    hooks.preToolUse = mergeHookBucket(hooks.preToolUse, {
      matcher: "Write|Edit|StrReplace",
      command: `${cmdPrefix} hook pre-edit --harness cursor`,
    });
    writeJsonObj(filePath, { ...doc, version: 1, hooks });
    return rel;
  }

  if (harness === "copilot") {
    hooks.PostToolUse = mergeHookBucket(hooks.PostToolUse, {
      matcher: "Edit|Write",
      hooks: [{ type: "command", command: `${cmdPrefix} hook post-edit --harness copilot --tier all`, timeout: 15 }],
    });
    writeJsonObj(filePath, { ...doc, hooks });
    return rel;
  }

  const matcher = harness === "codex" ? "Edit|Write|apply_patch" : "Edit|Write|MultiEdit";
  hooks.PreToolUse = mergeHookBucket(hooks.PreToolUse, {
    matcher,
    hooks: [{ type: "command", command: `${cmdPrefix} hook pre-edit --harness ${harness}`, timeout: 15 }],
  });
  hooks.PostToolUse = mergeHookBucket(hooks.PostToolUse, {
    matcher,
    hooks: [{ type: "command", command: `${cmdPrefix} hook post-edit --harness ${harness}`, timeout: 15 }],
  });
  hooks.Stop = mergeHookBucket(hooks.Stop, {
    matcher: ".*",
    hooks: [{ type: "command", command: `${cmdPrefix} hook stop --harness ${harness}`, timeout: 30 }],
  });
  writeJsonObj(filePath, { ...doc, hooks });
  return rel;
}

function removeHarnessManifest(repoRoot: string, harness: HookHarness): string | null {
  const filePath = manifestPathFor(repoRoot, harness);
  if (!fs.existsSync(filePath)) return null;
  const rel = path.relative(repoRoot, filePath).split(path.sep).join("/");

  if (harness === "copilot" || harness === "grok") {
    fs.unlinkSync(filePath);
    return rel;
  }

  const doc = readJsonObj(filePath);
  if (!isRecord(doc.hooks)) return null;
  const nextHooks: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(doc.hooks)) {
    const cleaned = stripHookBucket(v);
    if (cleaned.length > 0) nextHooks[k] = cleaned;
  }
  if (Object.keys(nextHooks).length === 0) {
    const { hooks: _removed, ...rest } = doc;
    void _removed;
    if (Object.keys(rest).length === 0 || (harness === "cursor" && Object.keys(rest).length === 1 && rest.version === 1)) {
      fs.unlinkSync(filePath);
    } else {
      writeJsonObj(filePath, rest);
    }
  } else {
    writeJsonObj(filePath, { ...doc, hooks: nextHooks });
  }
  return rel;
}

export function manageHooks(
  repoPath: string,
  action: HooksAdminAction,
  options: { harnesses?: readonly HookHarness[]; commandPrefix?: string } = {},
): HooksAdminResult {
  const repoRoot = path.resolve(repoPath);
  const configPath = path.join(repoRoot, ".verification", "hooks.json");
  const configRel = ".verification/hooks.json";
  const current = loadHookConfig(repoRoot);
  const selected: HookHarness[] =
    options.harnesses && options.harnesses.length > 0
      ? [...options.harnesses]
      : current.harnesses.length > 0
        ? current.harnesses
        : ["claude", "codex", "cursor"];
  const cmdPrefix = options.commandPrefix ?? "npx --no-install vstack";

  if (action === "status") {
    const claudeGlobalDisabled = (() => {
      const p = path.join(repoRoot, ".claude", "settings.json");
      if (!fs.existsSync(p)) return false;
      try {
        const d = JSON.parse(fs.readFileSync(p, "utf8")) as Record<string, unknown>;
        return d.disableAllHooks === true;
      } catch {
        return false;
      }
    })();
    const installed = ALL_HARNESSES.filter((h) => {
      if (h === "claude" && claudeGlobalDisabled) return false;
      const p = manifestPathFor(repoRoot, h);
      if (!fs.existsSync(p)) return false;
      try {
        const parsed: unknown = JSON.parse(fs.readFileSync(p, "utf8"));
        if (!isRecord(parsed) || parsed.disableAllHooks === true || !isRecord(parsed.hooks)) return false;
        if (h === "claude" || h === "codex") {
          const hasPre = Array.isArray(parsed.hooks.PreToolUse) && parsed.hooks.PreToolUse.some((e) => containsVstackCommand(e, "pre-edit", true));
          const hasPost = Array.isArray(parsed.hooks.PostToolUse) && parsed.hooks.PostToolUse.some((e) => containsVstackCommand(e, "post-edit", true));
          const hasStop = Array.isArray(parsed.hooks.Stop) && parsed.hooks.Stop.some((e) => containsVstackCommand(e, "stop", false));
          return hasPre && hasPost && hasStop;
        }
        if (h === "cursor") {
          return Array.isArray(parsed.hooks.preToolUse) && parsed.hooks.preToolUse.some((e) => containsVstackCommand(e, "pre-edit", true));
        }
        return Object.values(parsed.hooks).some(
          (bucket) => Array.isArray(bucket) && bucket.some((entry) => containsVstackCommand(entry)),
        );
      } catch {
        return false;
      }
    });
    const envDisabled = process.env.VSTACK_HOOK_DISABLED === "1";
    const enabled = current.enabled && !envDisabled && installed.length > 0;
    return {
      action,
      repoRoot,
      configPath: configRel,
      enabled,
      harnesses: installed,
      touchedManifests: installed.map((h) => path.relative(repoRoot, manifestPathFor(repoRoot, h)).split(path.sep).join("/")),
      summary: `hooks: ${enabled ? "ON" : "OFF"} (tier=${current.tier}, installed=[${installed.join(", ") || "none"}]${envDisabled ? ", VSTACK_HOOK_DISABLED=1" : ""})`,
    };
  }

  if (action === "on") {
    const touched = selected.map((h) => installHarnessManifest(repoRoot, h, cmdPrefix));
    const nextCfg: HookProjectConfig = {
      enabled: true,
      tier: current.tier,
      ...(current.auditLog ? { auditLog: current.auditLog } : {}),
      harnesses: selected,
    };
    writeJsonObj(configPath, nextCfg);
    return {
      action,
      repoRoot,
      configPath: configRel,
      enabled: true,
      harnesses: selected,
      touchedManifests: touched,
      summary: `hooks: ON — installed [${selected.join(", ")}] (${touched.join(", ")})`,
    };
  }

  if (action === "off") {
    const nextCfg: HookProjectConfig = {
      enabled: false,
      tier: current.tier,
      ...(current.auditLog ? { auditLog: current.auditLog } : {}),
      harnesses: current.harnesses,
    };
    writeJsonObj(configPath, nextCfg);
    return {
      action,
      repoRoot,
      configPath: configRel,
      enabled: false,
      harnesses: current.harnesses,
      touchedManifests: [configRel],
      summary: "hooks: OFF — automatic per-edit and stop hooks paused in .verification/hooks.json.",
    };
  }

  const removed: string[] = [];
  for (const h of ALL_HARNESSES) {
    const r = removeHarnessManifest(repoRoot, h);
    if (r) removed.push(r);
  }
  if (fs.existsSync(configPath)) {
    fs.unlinkSync(configPath);
    removed.push(configRel);
  }
  return {
    action,
    repoRoot,
    configPath: configRel,
    enabled: false,
    harnesses: [],
    touchedManifests: removed,
    summary: `hooks: RESET — removed Veristack hook entries (${removed.join(", ") || "none present"}).`,
  };
}

export function formatHooksStatus(result: HooksAdminResult): string {
  const lines = [result.summary];
  if (result.touchedManifests.length > 0) {
    lines.push(`  Manifests: ${result.touchedManifests.join(", ")}`);
  }
  return lines.join("\n");
}
