import { spawnSync } from "node:child_process";
import YAML from "yaml";
import type { ScannedFile } from "../discover.ts";
import { sanitizeShellBlock } from "./command-audit.ts";
import { runGitClean } from "./config-audit.ts";

export interface ActiveWorkflowInfo {
  file: string;
  isPrBlocking: boolean;
  triggers: string[];
  activeCommands: string[];
  scopedCommands?: Array<{ cwd: string; command: string }>;
  deadJobs: string[];
}

export interface CodeownersPerimeterResult {
  hasFile: boolean;
  file?: string;
  uncoveredSurfaces: string[];
  passed: boolean;
}

const VALID_OWNER_TOKEN = /^(?:@[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?(?:\/[A-Za-z0-9_.-]+)?|[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})$/;
const ALLOWED_SHELLS = new Set(["bash", "sh", "pwsh", "powershell", "zsh"]);

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
  if (val === undefined || val === null || val === false) return false;
  if (typeof val === "string") {
    const norm = val.trim().replace(/^\$\{\{\s*|\s*\}\}$/g, "").trim().toLowerCase();
    return norm !== "false";
  }
  return true;
}

function isAllowedShell(shellVal: unknown): boolean {
  if (shellVal === undefined || shellVal === null) return true;
  if (typeof shellVal !== "string") return false;
  return ALLOWED_SHELLS.has(shellVal.trim().toLowerCase());
}

function isBlockingTriggerConfig(name: string, cfg: unknown): boolean {
  if (name === "merge_group") return true;
  if (name !== "pull_request" && name !== "push") return false;
  if (!isRecord(cfg)) return true;
  const defaultBranches = new Set(["main", "master", "trunk", "**", "*"]);
  if (name === "push" && Array.isArray(cfg.tags) && cfg.tags.length > 0 && (!Array.isArray(cfg.branches) || cfg.branches.length === 0)) {
    return false;
  }
  if (Array.isArray(cfg.paths) && cfg.paths.length > 0) return false;
  if (Array.isArray(cfg["paths-ignore"]) && cfg["paths-ignore"].length > 0) {
    const SAFE_DOCS_IGNORE = /^(?:\*\*\/)?(?:docs\/.+|README(?:\.[^/]+)?|CHANGELOG(?:\.[^/]+)?|LICENSE(?:\.[^/]+)?|\*\.md|\*\*\/\*\.md|\*\.txt|\*\.png|\*\.svg|\.vscode\/.+)$/i;
    const risky = cfg["paths-ignore"].some((p) => typeof p !== "string" || !SAFE_DOCS_IGNORE.test(p.trim()));
    if (risky) return false;
  }
  if (Array.isArray(cfg["branches-ignore"]) && cfg["branches-ignore"].length > 0) {
    if (cfg["branches-ignore"].some((b) => typeof b === "string" && defaultBranches.has(b.trim()))) return false;
  }
  if (Array.isArray(cfg.branches) && cfg.branches.length > 0) {
    if (!cfg.branches.some((b) => typeof b === "string" && defaultBranches.has(b.trim()))) return false;
  }
  if (name === "pull_request" && Array.isArray(cfg.types) && cfg.types.length > 0) {
    const typeSet = new Set(cfg.types.filter((t): t is string => typeof t === "string"));
    if (!typeSet.has("opened") || !typeSet.has("synchronize")) return false;
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
  const scopedCommands: Array<{ cwd: string; command: string }> = [];
  const wfDefaults = isRecord(doc.defaults) && isRecord(doc.defaults.run) ? doc.defaults.run.shell : undefined;
  const wfWorkDir = isRecord(doc.defaults) && isRecord(doc.defaults.run) ? doc.defaults.run["working-directory"] : undefined;
  const BAD_ENV_KEY = /^(?:VSTACK_ALLOW_MANIFEST_CHANGE|VSTACK_HOOK_DISABLED|NODE_OPTIONS|BUN_OPTIONS|BUN_INSTALL|PYTEST_ADDOPTS|PYTEST_PLUGINS|PYTHONSTARTUP|PYTHONPATH|VIRTUAL_ENV|GOFLAGS|GOENV|GOWORK|RUSTFLAGS|RUSTC|RUSTC_WRAPPER|RUSTC_WORKSPACE_WRAPPER|RUSTUP_HOME|CARGO_HOME|CARGO_BUILD_|CARGO_ENCODED_RUSTFLAGS|CARGO_TARGET_|DOTNET_STARTUP_HOOKS|DOTNET_ADDITIONAL_DEPS|DOTNET_ROOT|LD_PRELOAD|DYLD_INSERT_LIBRARIES|PATH|BASH_ENV|ENV|GIT_DIR|GIT_WORK_TREE|GIT_INDEX_FILE|GIT_ATTRIBUTES|GIT_CONFIG_)/i;
  const GITHUB_ENV_POISON = /\bGITHUB_(?:ENV|PATH)\b/i;
  const hasPoisonedEnv = (envObj: unknown): boolean => isRecord(envObj) && Object.keys(envObj).some((k) => BAD_ENV_KEY.test(k));
  const wfPoisoned = hasPoisonedEnv(doc.env);
  for (const [jobId, jobVal] of Object.entries(rawJobs)) {
    if (deadJobSet.has(jobId) || !isRecord(jobVal)) continue;
    if (wfPoisoned || hasPoisonedEnv(jobVal.env)) continue;
    const jobShell = isRecord(jobVal.defaults) && isRecord(jobVal.defaults.run) ? jobVal.defaults.run.shell : wfDefaults;
    const jobWorkDir = isRecord(jobVal.defaults) && isRecord(jobVal.defaults.run) ? jobVal.defaults.run["working-directory"] : wfWorkDir;
    const steps = Array.isArray(jobVal.steps) ? jobVal.steps : [];
    let jobEnvPoisoned = false;
    for (const step of steps) {
      if (!isRecord(step) || hasPoisonedEnv(step.env)) continue;
      if (typeof step.uses === "string" && step.uses.trim().startsWith("./")) { jobEnvPoisoned = true; continue; }
      if (typeof step.run === "string" && GITHUB_ENV_POISON.test(step.run)) { jobEnvPoisoned = true; continue; }
      if (jobEnvPoisoned) continue;
      if (!isUnconditionalIf(step.if) || isContinueOnError(step["continue-on-error"])) continue;
      if (!isAllowedShell(step.shell ?? jobShell)) continue;
      const rawWd = step["working-directory"] ?? jobWorkDir;
      const cwd = typeof rawWd === "string" ? rawWd.trim().replace(/^\.\/+/, "").replace(/\/+$/, "") : "";
      if (cwd.startsWith("/") || cwd.includes("..")) continue;
      if (typeof step.run === "string") {
        const cmds = sanitizeShellBlock(step.run);
        for (const cmd of cmds) {
          activeCommands.push(cmd);
          scopedCommands.push({ cwd: cwd === "." ? "" : cwd, command: cmd });
        }
      }
    }
  }

  return {
    file: file.rel,
    isPrBlocking,
    triggers,
    activeCommands,
    scopedCommands,
    deadJobs: [...deadJobSet].sort(),
  };
}

export function globMatchesPath(pattern: string, target: string): boolean {
  const raw = pattern.trim();
  const normTarget = target.replace(/^\/+/, "");
  if (!raw || raw.startsWith("!")) return false;
  if (raw === "*" || raw === "**") return true;
  const anchored = raw.startsWith("/");
  const isDir = raw.endsWith("/");
  const body = raw.replace(/^\/+/, "").replace(/\/+$/, "");
  if (!body) return false;
  const hasSlash = body.includes("/");
  const hasWildcard = body.includes("*") || body.includes("?");
  if (!hasWildcard) {
    if (anchored || hasSlash) {
      return normTarget === body || normTarget.startsWith(`${body}/`);
    }
    if (isDir) {
      return normTarget.startsWith(`${body}/`) || normTarget.includes(`/${body}/`);
    }
    return normTarget === body || normTarget.startsWith(`${body}/`) || normTarget.endsWith(`/${body}`) || normTarget.includes(`/${body}/`);
  }
  const escaped = body
    .replace(/[.+^${}()|[\]\\]/g, "\\$&")
    .replace(/\*\*/g, "__DBL__")
    .replace(/\*/g, "[^/]*")
    .replace(/\?/g, "[^/]")
    .replace(/__DBL__/g, ".*");
  const prefix = anchored || hasSlash ? "^" : "(?:^|/)";
  const suffix = isDir ? "/.*$" : "$";
  return new RegExp(`${prefix}${escaped}${suffix}`).test(normTarget);
}

export function auditCodeownersPerimeter(
  files: readonly ScannedFile[],
  allRelPaths: readonly string[],
): CodeownersPerimeterResult {
  const coFile =
    files.find((f) => f.rel === ".github/CODEOWNERS") ??
    files.find((f) => f.rel === "CODEOWNERS") ??
    files.find((f) => f.rel === "docs/CODEOWNERS");
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
  for (const p of allRelPaths) {
    if (p.startsWith(".verification/laws/") && p.endsWith(".laws.json")) surfaces.push(p);
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
  const remote = runGitClean(repoRoot, ["remote", "get-url", "origin"]);
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
  return evaluateBranchProtectionJson(defaultBranch, api.stdout);
}

export function evaluateBranchProtectionJson(defaultBranch: string, rawJson: string): {
  checked: boolean;
  passed: boolean;
  requiredChecks: string[];
  codeOwnerReviewsRequired: boolean;
  adminsEnforced: boolean;
  detail: string;
} {
  try {
    const parsed = JSON.parse(rawJson) as {
      required_status_checks?: { contexts?: string[]; checks?: Array<{ context?: string }> };
      required_pull_request_reviews?: {
        require_code_owner_reviews?: boolean;
        required_approving_review_count?: number;
        dismiss_stale_reviews?: boolean;
      };
      enforce_admins?: { enabled?: boolean };
      allow_force_pushes?: { enabled?: boolean };
    };
    const checks = [
      ...(parsed.required_status_checks?.contexts ?? []),
      ...(parsed.required_status_checks?.checks?.map((c) => c.context ?? "").filter(Boolean) ?? []),
    ];
    const hasVeristack = checks.some((c) => /^(?:self-verify-vstack-strict|veristack(?:-strict)?|vstack-strict|verify-ts)$/i.test(c.trim()));
    const prRev = parsed.required_pull_request_reviews;
    const codeOwnerReviewsRequired = Boolean(prRev?.require_code_owner_reviews);
    const hasApprovals = (prRev?.required_approving_review_count ?? 0) >= 1;
    const dismissStale = Boolean(prRev?.dismiss_stale_reviews);
    const adminsEnforced = Boolean(parsed.enforce_admins?.enabled);
    const noForcePush = parsed.allow_force_pushes?.enabled !== true;
    const passed =
      checks.length > 0 &&
      hasVeristack &&
      codeOwnerReviewsRequired &&
      hasApprovals &&
      dismissStale &&
      adminsEnforced &&
      noForcePush;
    return {
      checked: true,
      passed,
      requiredChecks: [...new Set(checks)],
      codeOwnerReviewsRequired,
      adminsEnforced,
      detail: passed
        ? `Branch '${defaultBranch}' enforces strict Veristack check, CODEOWNERS reviews (>=1, dismiss stale), admins, and blocks force-push.`
        : `Incomplete protection on '${defaultBranch}': veristackCheck=${hasVeristack}, codeOwnerReviews=${codeOwnerReviewsRequired}, approvals>=1=${hasApprovals}, dismissStale=${dismissStale}, enforceAdmins=${adminsEnforced}, noForcePush=${noForcePush}.`,
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
