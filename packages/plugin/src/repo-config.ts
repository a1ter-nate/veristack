import fs from "node:fs";
import path from "node:path";
import type { Finding, Severity, SoundnessClass } from "./types.ts";

export type RuleLevel = "off" | Severity;

export interface RetiringImportRule {
  module: string;
  replacement?: string;
  allowedImporters?: string[];
}

export interface VstackConfig {
  configPath?: string;
  rules: Record<string, RuleLevel>;
  ignore: string[];
  retiring?: RetiringImportRule[];
  forbidNewImports?: string[];
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

function parseBackslidingConfig(obj: Record<string, unknown>): { retiring: RetiringImportRule[]; forbidNewImports: string[] } {
  const forbidNewImports: string[] = [];
  if (Array.isArray(obj.forbidNewImports)) {
    for (const item of obj.forbidNewImports) if (typeof item === "string" && item.trim().length > 0) forbidNewImports.push(item.trim());
  }
  const retiring: RetiringImportRule[] = [];
  if (Array.isArray(obj.retiring)) {
    for (const item of obj.retiring) {
      if (typeof item === "string" && item.trim().length > 0) {
        retiring.push({ module: item.trim() });
      } else if (item && typeof item === "object" && !Array.isArray(item)) {
        const rec = item as Record<string, unknown>;
        if (typeof rec.module === "string" && rec.module.trim().length > 0) {
          const allowed = Array.isArray(rec.allowedImporters)
            ? rec.allowedImporters.filter((p): p is string => typeof p === "string" && p.trim().length > 0).map((p) => p.trim())
            : undefined;
          retiring.push({
            module: rec.module.trim(),
            ...(typeof rec.replacement === "string" && rec.replacement.trim() ? { replacement: rec.replacement.trim() } : {}),
            ...(allowed && allowed.length > 0 ? { allowedImporters: allowed } : {}),
          });
        }
      }
    }
  }
  return { retiring, forbidNewImports };
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
    for (const item of obj.disabledRules) if (typeof item === "string" && item.trim().length > 0) rules[item.trim()] = "off";
  }
  if (obj.rules && typeof obj.rules === "object" && !Array.isArray(obj.rules)) {
    for (const [key, val] of Object.entries(obj.rules as Record<string, unknown>)) {
      if (typeof val === "string" && VALID_LEVELS.has(val)) rules[key.trim()] = val as RuleLevel;
    }
  }
  const ignore = Array.isArray(obj.ignore) ? obj.ignore.filter((x): x is string => typeof x === "string" && x.trim().length > 0).map((x) => x.trim()) : [];
  const { retiring, forbidNewImports } = parseBackslidingConfig(obj);
  const rel = path.relative(repoRoot, filePath).split(path.sep).join("/");
  return {
    configPath: rel || path.basename(filePath),
    rules,
    ignore,
    ...(retiring.length > 0 ? { retiring } : {}),
    ...(forbidNewImports.length > 0 ? { forbidNewImports } : {}),
  };
}

const HYGIENE_ONLY_RULES = new Set([
  "no-comments",
  "max-file-lines",
  "long-file",
  "wide-directory",
  "tiger-function-length",
  "tiger-naming-convention",
  "tiger-interface-surface",
  "tiger-var-near-use",
  "tiger-push-ifs-up-fors-down",
  "tiger-low-assertion-density",
  "agent-doc-bloat",
  "agent-doc-unpromoted-rules",
  "validate-and-discard",
  "repeated-defensive-guard",
  "competing-paved-paths",
  "effect-passthrough-service-wrapper",
  "statechart-missing-exit-cleanup",
  "statechart-unhandled-event",
  "liskov-strengthened-precondition",
]);

export function soundnessClassForFinding(
  f: Pick<Finding, "rule" | "category" | "severity" | "soundness">,
): SoundnessClass {
  if (f.soundness) return f.soundness;
  if (f.category === "no-comments" || HYGIENE_ONLY_RULES.has(f.rule)) return "hygiene-lint";
  if (f.category === "cheat" || f.category === "oracle-lock" || f.severity === "error") return "incorrectness-witness";
  if (/^(?:aspirator-|sm-crash-|effect-defect-|io-inside-db-|liskov-|statechart-unreachable|statechart-overlapping|backsliding-|typestate-|temporal-protocol-|cloud-|ast-|law-|affine-|rust-|go-|py-|sql-|shell-)/.test(f.rule)) {
    return "incorrectness-witness";
  }
  return "hygiene-lint";
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
  if (!Array.isArray(findings)) throw new Error("findings must be an array.");
  if (!config) throw new Error("config is required.");
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
