import { spawnSync } from "node:child_process";
import YAML from "yaml";
import type { ScannedFile } from "../discover.ts";

export interface ActiveWorkflowInfo {
  file: string;
  isPrBlocking: boolean;
  triggers: string[];
  activeCommands: string[];
  deadJobs: string[];
}

export interface CodeownersPerimeterResult {
  hasFile: boolean;
  file?: string;
  uncoveredSurfaces: string[];
  passed: boolean;
}

const VALID_CODEOWNERS_PATHS = new Set([".github/CODEOWNERS", "CODEOWNERS", "docs/CODEOWNERS"]);
const VALID_OWNER_TOKEN = /^(?:@[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?(?:\/[A-Za-z0-9_.-]+)?|[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})$/;

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isUnconditionalIf(cond: unknown): boolean {
  if (cond === undefined || cond === null) return true;
  if (typeof cond === "boolean") return cond === true;
  if (typeof cond !== "string") return false;
  const norm = cond.trim().replace(/^\$\{\{\s*|\s*\}\}$/g, "").trim().toLowerCase();
  return norm === "true" || norm === "success()" || norm === "always()";
}

function isContinueOnError(val: unknown): boolean {
  if (val === true) return true;
  if (typeof val === "string") {
    const norm = val.trim().replace(/^\$\{\{\s*|\s*\}\}$/g, "").trim().toLowerCase();
    return norm === "true";
  }
  return false;
}

function stripShellComment(line: string): string {
  let inSingle = false;
  let inDouble = false;
  for (let i = 0; i < line.length; i++) {
    const ch = line[i] ?? "";
    if (ch === "'" && !inDouble) inSingle = !inSingle;
    else if (ch === '"' && !inSingle && line[i - 1] !== "\\") inDouble = !inDouble;
    else if (ch === "#" && !inSingle && !inDouble) {
      if (i === 0 || /\s/.test(line[i - 1] ?? "")) return line.slice(0, i);
    }
  }
  return line;
}

export function sanitizeShellBlock(runScript: string): string[] {
  const active: string[] = [];
  let setPlusE = false;
  for (const raw of runScript.split(/\r?\n/)) {
    const trimmed = stripShellComment(raw).trim();
    if (!trimmed) continue;
    if (/^set\s+\+e\b/.test(trimmed)) {
      setPlusE = true;
      continue;
    }
    if (/^set\s+-e\b/.test(trimmed)) {
      setPlusE = false;
      continue;
    }
    if (/^exit\s+0\b/.test(trimmed)) break;
    if (setPlusE) continue;
    if (/^(?:echo|printf|true)(?:\s|$)/.test(trimmed)) continue;
    if (/^:(?:\s|$)/.test(trimmed)) continue;
    if (/^false\s*&&/.test(trimmed)) continue;
    if (/\|\|\s*(?:true|echo|printf|:|exit\s+0)\b/.test(trimmed)) continue;
    if (/\s--help(?:\s|$)/.test(trimmed)) continue;
    active.push(trimmed);
  }
  return active;
}

function isBlockingTriggerConfig(name: string, cfg: unknown): boolean {
  if (name === "merge_group") return true;
  if (name !== "pull_request" && name !== "push") return false;
  if (!isRecord(cfg)) return true;
  if (Array.isArray(cfg.paths) && cfg.paths.length > 0) return false;
  if (Array.isArray(cfg["paths-ignore"]) && cfg["paths-ignore"].includes("**")) return false;
  if (Array.isArray(cfg["branches-ignore"]) && cfg["branches-ignore"].includes("**")) return false;
  if (name === "push" && Array.isArray(cfg.branches) && cfg.branches.length > 0) {
    const defaultBranches = new Set(["main", "master", "trunk", "**", "*"]);
    if (!cfg.branches.some((b) => typeof b === "string" && defaultBranches.has(b))) return false;
  }
  if (name === "pull_request" && Array.isArray(cfg.types) && cfg.types.length > 0) {
    const blockingTypes = new Set(["opened", "synchronize", "reopened"]);
    if (!cfg.types.some((t) => typeof t === "string" && blockingTypes.has(t))) return false;
  }
  return true;
}

function extractTriggers(onField: unknown): { triggers: string[]; isPrBlocking: boolean } {
  const triggers: string[] = [];
  let isPrBlocking = false;
  if (typeof onField === "string") {
    triggers.push(onField);
    isPrBlocking = isBlockingTriggerConfig(onField, undefined);
  } else if (Array.isArray(onField)) {
    for (const item of onField) {
      if (typeof item === "string") {
        triggers.push(item);
        if (isBlockingTriggerConfig(item, undefined)) isPrBlocking = true;
      }
    }
  } else if (isRecord(onField)) {
    for (const [key, val] of Object.entries(onField)) {
      triggers.push(key);
      if (isBlockingTriggerConfig(key, val)) isPrBlocking = true;
    }
  }
  return { triggers: [...new Set(triggers)], isPrBlocking };
}

export function parseGitHubWorkflow(file: ScannedFile): ActiveWorkflowInfo {
  let doc: unknown;
  try {
    doc = YAML.parse(file.content);
  } catch {
    return { file: file.rel, isPrBlocking: false, triggers: [], activeCommands: [], deadJobs: ["<invalid-yaml>"] };
  }
  if (!isRecord(doc)) {
    return { file: file.rel, isPrBlocking: false, triggers: [], activeCommands: [], deadJobs: [] };
  }

  const onField = doc.on ?? doc.true;
  const { triggers, isPrBlocking } = extractTriggers(onField);
  const rawJobs = isRecord(doc.jobs) ? doc.jobs : {};

  const deadJobSet = new Set<string>();
  for (const [jobId, jobVal] of Object.entries(rawJobs)) {
    if (!isRecord(jobVal)) continue;
    if (!isUnconditionalIf(jobVal.if) || isContinueOnError(jobVal["continue-on-error"])) {
      deadJobSet.add(jobId);
    }
  }

  let changed = true;
  while (changed) {
    changed = false;
    for (const [jobId, jobVal] of Object.entries(rawJobs)) {
      if (deadJobSet.has(jobId) || !isRecord(jobVal)) continue;
      const needs = jobVal.needs;
      const depList = typeof needs === "string" ? [needs] : Array.isArray(needs) ? needs.filter((n): n is string => typeof n === "string") : [];
      if (depList.some((dep) => deadJobSet.has(dep))) {
        deadJobSet.add(jobId);
        changed = true;
      }
    }
  }

  const activeCommands: string[] = [];
  for (const [jobId, jobVal] of Object.entries(rawJobs)) {
    if (deadJobSet.has(jobId) || !isRecord(jobVal)) continue;
    const steps = Array.isArray(jobVal.steps) ? jobVal.steps : [];
    for (const step of steps) {
      if (!isRecord(step)) continue;
      if (!isUnconditionalIf(step.if) || isContinueOnError(step["continue-on-error"])) continue;
      if (typeof step.run === "string") {
        activeCommands.push(...sanitizeShellBlock(step.run));
      }
    }
  }

  return {
    file: file.rel,
    isPrBlocking,
    triggers,
    activeCommands,
    deadJobs: [...deadJobSet].sort(),
  };
}

function globMatchesPath(pattern: string, target: string): boolean {
  const normPat = pattern.trim().replace(/^\/+/, "");
  const normTarget = target.replace(/^\/+/, "");
  if (!normPat || normPat.startsWith("!")) return false;
  if (normPat === "*" || normPat === "**") return true;
  if (normPat === normTarget) return true;
  if (normPat.endsWith("/") && (normTarget.startsWith(normPat) || `${normTarget}/` === normPat)) return true;
  const escaped = normPat
    .replace(/[.+^${}()|[\]\\]/g, "\\$&")
    .replace(/\*\*/g, "__DBL__")
    .replace(/\*/g, "[^/]*")
    .replace(/__DBL__/g, ".*");
  return new RegExp(`^${escaped}$`).test(normTarget);
}

export function auditCodeownersPerimeter(
  files: readonly ScannedFile[],
  allRelPaths: readonly string[],
): CodeownersPerimeterResult {
  const coFile = files.find((f) => VALID_CODEOWNERS_PATHS.has(f.rel));
  if (!coFile) {
    return { hasFile: false, uncoveredSurfaces: [".github/CODEOWNERS"], passed: false };
  }

  const rules: Array<{ pattern: string; owners: string[] }> = [];
  for (const raw of coFile.content.split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || line.startsWith("#")) continue;
    const parts = line.split(/\s+/);
    const pattern = parts[0] ?? "";
    if (!pattern) continue;
    const owners = parts.slice(1).filter((p) => VALID_OWNER_TOKEN.test(p));
    rules.push({ pattern, owners });
  }

  if (!rules.some((r) => r.owners.length > 0)) {
    return { hasFile: true, file: coFile.rel, uncoveredSurfaces: ["CODEOWNERS has zero valid owners"], passed: false };
  }

  const allSet = new Set(allRelPaths);
  const surfaces: string[] = [
    ".github/workflows/ci.yml",
    ".verification/rungs.json",
    ".verification/behavior-changes.json",
    coFile.rel,
  ];
  for (const wf of allRelPaths) {
    if (wf.startsWith(".github/workflows/") && (wf.endsWith(".yml") || wf.endsWith(".yaml"))) {
      surfaces.push(wf);
    }
  }
  const optionalSurfaces = [
    ".vstackignore",
    ".vstack.json",
    "lefthook.yml",
    "package.json",
    ".verification/control-plan.json",
    ".verification/escapes.json",
    ".verification/invariants.json",
    ".verification/chokepoints.json",
  ];
  for (const opt of optionalSurfaces) {
    if (allSet.has(opt)) surfaces.push(opt);
  }

  const uniqueSurfaces = [...new Set(surfaces)];
  const uncovered = uniqueSurfaces.filter((surf) => {
    let lastOwners: string[] = [];
    for (const rule of rules) {
      if (globMatchesPath(rule.pattern, surf)) {
        lastOwners = rule.owners;
      }
    }
    return lastOwners.length === 0;
  });

  return {
    hasFile: true,
    file: coFile.rel,
    uncoveredSurfaces: uncovered,
    passed: uncovered.length === 0,
  };
}

export function checkGitHubBranchProtection(repoRoot: string): {
  checked: boolean;
  passed: boolean;
  requiredChecks: string[];
  codeOwnerReviewsRequired: boolean;
  adminsEnforced: boolean;
  detail: string;
} {
  const remote = spawnSync("git", ["-C", repoRoot, "remote", "get-url", "origin"], { encoding: "utf8" });
  const match = /github\.com[:/]([^/]+\/[^/]+?)(?:\.git)?$/i.exec((remote.stdout ?? "").trim());
  if (!match?.[1]) {
    return {
      checked: false,
      passed: false,
      requiredChecks: [],
      codeOwnerReviewsRequired: false,
      adminsEnforced: false,
      detail: "No GitHub origin remote detected.",
    };
  }
  const slug = match[1];
  const repoInfo = spawnSync("gh", ["api", `repos/${slug}`, "--jq", ".default_branch"], {
    encoding: "utf8",
    timeout: 10_000,
  });
  const defaultBranch = repoInfo.status === 0 && repoInfo.stdout.trim() ? repoInfo.stdout.trim() : "main";

  const api = spawnSync("gh", ["api", `repos/${slug}/branches/${defaultBranch}/protection`], {
    encoding: "utf8",
    timeout: 10_000,
  });
  if (api.status !== 0) {
    const stderr = (api.stderr ?? api.stdout ?? "").trim();
    const isUnprotected = /404|Branch not protected/i.test(stderr);
    return {
      checked: isUnprotected,
      passed: false,
      requiredChecks: [],
      codeOwnerReviewsRequired: false,
      adminsEnforced: false,
      detail: isUnprotected
        ? `Branch '${defaultBranch}' on ${slug} is NOT protected (HTTP 404).`
        : `Unable to read branch protection for ${slug}/${defaultBranch}: ${stderr.slice(0, 140)}`,
    };
  }

  try {
    const parsed = JSON.parse(api.stdout) as {
      required_status_checks?: { contexts?: string[]; checks?: Array<{ context?: string }> };
      required_pull_request_reviews?: { require_code_owner_reviews?: boolean };
      enforce_admins?: { enabled?: boolean };
    };
    const checks = [
      ...(parsed.required_status_checks?.contexts ?? []),
      ...(parsed.required_status_checks?.checks?.map((c) => c.context ?? "").filter(Boolean) ?? []),
    ];
    const hasVeristack = checks.some((c) => /veristack|vstack|self-verify-vstack/i.test(c));
    const codeOwnerReviewsRequired = Boolean(parsed.required_pull_request_reviews?.require_code_owner_reviews);
    const adminsEnforced = Boolean(parsed.enforce_admins?.enabled);
    const passed = checks.length > 0 && hasVeristack && codeOwnerReviewsRequired && adminsEnforced;
    return {
      checked: true,
      passed,
      requiredChecks: [...new Set(checks)],
      codeOwnerReviewsRequired,
      adminsEnforced,
      detail: passed
        ? `Branch '${defaultBranch}' enforces Veristack check, CODEOWNERS reviews, and admins.`
        : `Incomplete protection on '${defaultBranch}': veristackCheck=${hasVeristack}, codeOwnerReviews=${codeOwnerReviewsRequired}, enforceAdmins=${adminsEnforced}.`,
    };
  } catch {
    return {
      checked: false,
      passed: false,
      requiredChecks: [],
      codeOwnerReviewsRequired: false,
      adminsEnforced: false,
      detail: "Failed to parse branch protection JSON.",
    };
  }
}
