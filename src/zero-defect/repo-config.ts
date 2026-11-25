import fs from "node:fs";
import path from "node:path";
import type { Finding, Severity } from "../types.ts";

export type RuleLevel = "off" | Severity;

export interface VstackConfig {
  configPath?: string;
  rules: Record<string, RuleLevel>;
  ignore: string[];
}

export interface AppliedConfigResult {
  findings: Finding[];
  suppressedCount: number;
  disabledRules: string[];
}

const VALID_LEVELS = new Set<string>(["off", "error", "warn", "info"]);

function resolveConfigFile(repoRoot: string, explicitConfigPath?: string): string | undefined {
  if (explicitConfigPath) {
    const resolved = path.isAbsolute(explicitConfigPath)
      ? explicitConfigPath
      : path.resolve(repoRoot, explicitConfigPath);
    if (!fs.existsSync(resolved)) {
      throw new Error(`Config file not found: ${explicitConfigPath}`);
    }
    return resolved;
  }
  const candidates = [
    path.join(repoRoot, ".vstack.json"),
    path.join(repoRoot, ".verification", "vstack.json"),
  ];
  for (const candidate of candidates) {
    if (fs.existsSync(candidate)) return candidate;
  }
  return undefined;
}

export function loadRepoConfig(repoRoot: string, explicitConfigPath?: string): VstackConfig {
  const filePath = resolveConfigFile(repoRoot, explicitConfigPath);
  if (!filePath) return { rules: {}, ignore: [] };

  let raw: unknown;
  try {
    raw = JSON.parse(fs.readFileSync(filePath, "utf8"));
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    throw new Error(`Invalid JSON in ${path.relative(repoRoot, filePath) || filePath}: ${msg}`);
  }

  if (!raw || typeof raw !== "object" || Array.isArray(raw)) {
    throw new Error(`Config ${path.relative(repoRoot, filePath)} must be a JSON object.`);
  }

  const obj = raw as Record<string, unknown>;
  const rules: Record<string, RuleLevel> = {};

  if (Array.isArray(obj.disabledRules)) {
    for (const item of obj.disabledRules) {
      if (typeof item === "string" && item.trim().length > 0) {
        rules[item.trim()] = "off";
      }
    }
  }

  if (obj.rules && typeof obj.rules === "object" && !Array.isArray(obj.rules)) {
    for (const [key, val] of Object.entries(obj.rules as Record<string, unknown>)) {
      if (typeof val === "string" && VALID_LEVELS.has(val)) {
        rules[key.trim()] = val as RuleLevel;
      }
    }
  }

  const ignore: string[] = [];
  if (Array.isArray(obj.ignore)) {
    for (const item of obj.ignore) {
      if (typeof item === "string" && item.trim().length > 0) {
        ignore.push(item.trim());
      }
    }
  }

  const rel = path.relative(repoRoot, filePath).split(path.sep).join("/");
  return { configPath: rel || path.basename(filePath), rules, ignore };
}

export function isRuleDisabled(
  ruleOrCategory: string,
  config: VstackConfig,
  extraDisabled?: readonly string[],
): boolean {
  if (extraDisabled?.includes(ruleOrCategory)) return true;
  return config.rules[ruleOrCategory] === "off";
}

export function applyRepoConfig(
  findings: readonly Finding[],
  config: VstackConfig,
  extraDisabled?: readonly string[],
): AppliedConfigResult {
  const extraSet = new Set((extraDisabled ?? []).map((r) => r.trim()).filter(Boolean));
  const disabledSet = new Set<string>(extraSet);
  for (const [rule, level] of Object.entries(config.rules)) {
    if (level === "off") disabledSet.add(rule);
  }

  if (disabledSet.size === 0 && Object.keys(config.rules).length === 0) {
    return { findings: [...findings], suppressedCount: 0, disabledRules: [] };
  }

  const kept: Finding[] = [];
  let suppressedCount = 0;

  for (const f of findings) {
    if (disabledSet.has(f.rule) || disabledSet.has(f.category)) {
      suppressedCount += 1;
      continue;
    }
    const override = config.rules[f.rule] ?? config.rules[f.category];
    if (override && override !== "off" && override !== f.severity) {
      kept.push({ ...f, severity: override });
    } else {
      kept.push(f);
    }
  }

  return {
    findings: kept,
    suppressedCount,
    disabledRules: [...disabledSet].sort(),
  };
}
