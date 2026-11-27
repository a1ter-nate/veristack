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
  deployCommands?: string[];
  ignoredPaths?: string[];
  matchedPaths?: string[];
  hasPrOrPushTrigger?: boolean;
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

function isUnconditionalIf(cond: unknown, falsyInputs?: ReadonlySet<string>): boolean {
  if (cond === undefined || cond === null) return true;
  if (typeof cond === "boolean") return cond === true;
  if (typeof cond !== "string") return false;
  let norm = cond.trim().replace(/^\$\{\{\s*|\s*\}\}$/g, "").trim().toLowerCase();
  if (norm === "true" || norm === "success()" || norm === "always()") return true;
  if (/\b(?:false|failure\s*\(|cancelled\s*\(|workflow_dispatch|skip)\b/.test(norm)) return false;
  if (falsyInputs && falsyInputs.size > 0) {
    const parts = norm.split(/\s*&&\s*/).filter((p) => {
      const m = /^!inputs\.([a-z0-9_-]+)$/.exec(p.trim());
      return !(m?.[1] && falsyInputs.has(m[1]));
    });
    if (parts.length === 0) return true;
    norm = parts.join(" && ");
  }
  if (norm === "!github.event.pull_request.draft" || norm === "github.event.pull_request.draft == false") return true;
  norm = norm.replace(/^!github\.event\.pull_request\.draft\s*&&\s*/, "").replace(/\s*&&\s*!github\.event\.pull_request\.draft$/, "").trim();
  if (/^matrix\.[a-z0-9_.-]+\s*(?:==|!=)\s*['"][^'"]*['"](?:\s*&&\s*matrix\.[a-z0-9_.-]+\s*(?:==|!=)\s*['"][^'"]*['"])*$/.test(norm)) return true;
  if (/^needs\.[a-z0-9_-]+\.outputs\.[a-z0-9_-]+\s*(?:==|!=)\s*['"](?:true|false)['"]/.test(norm)) return true;
  if (/^github\.event_name\s*!=\s*['"]pull_request['"]\s*\|\|/.test(norm)) return true;
  if (/^github\.repository\s*!=\s*['"][^'"]+['"]/.test(norm)) return true;
  return false;
}

function isMainPushDeployIf(cond: unknown): boolean {
  if (typeof cond !== "string") return false;
  const norm = cond.trim().replace(/^\$\{\{\s*|\s*\}\}$/g, "").trim().toLowerCase();
  return /^(?:github\.event_name\s*==\s*['"]push['"]\s*&&\s*)?github\.ref\s*==\s*['"]refs\/heads\/(?:main|master)['"]$/.test(norm);
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
  const s = shellVal.trim().toLowerCase();
  return ALLOWED_SHELLS.has(s) || /^(?:bash|sh|zsh)(?:\s+(?:--noprofile|--norc|-[a-z]*o\s+pipefail|-[a-z]*e[a-z]*|\{0\}))+$/.test(s);
}

const SAFE_DOCS_IGNORE =
  /^(?:\*\*\/)?(?:docs\/.+|README(?:\.[^/]+)?|CHANGELOG(?:\.[^/]+)?|LICENSE(?:\.[^/]+)?|\*\.md|\*\*\/\*\.md|\*\.txt|\*\.png|\*\.svg|\.vscode\/.+|\.gitignore|\.gitattributes|\.editorconfig)$/i;

function isBlockingTriggerConfig(name: string, cfg: unknown, defaultBranch?: string): boolean {
  if (name === "merge_group") return true;
  if (name !== "pull_request" && name !== "push") return false;
  if (!isRecord(cfg)) return true;
  const defaultBranches = new Set(["main", "master", "trunk", "**", "*", ...(defaultBranch ? [defaultBranch] : [])]);
  if (name === "push" && Array.isArray(cfg.tags) && cfg.tags.length > 0 && (!Array.isArray(cfg.branches) || cfg.branches.length === 0)) {
    return false;
  }
  if (Array.isArray(cfg.paths) && cfg.paths.length > 0) return false;
  if (Array.isArray(cfg["paths-ignore"]) && cfg["paths-ignore"].length > 0) {
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

function extractTriggers(onField: unknown, defaultBranch?: string): {
  triggers: string[]; isPrBlocking: boolean; ignoredPaths: string[]; matchedPaths: string[]; hasPrOrPushTrigger: boolean; falsyInputs: Set<string>;
} {
  const triggers: string[] = [];
  const ignoredPaths: string[] = [];
  const matchedPaths: string[] = [];
  const falsyInputs = new Set<string>();
  let isPrBlocking = false;
  let hasPrOrPushTrigger = false;
  const collectPaths = (name: string, cfg: unknown): void => {
    if ((name === "workflow_dispatch" || name === "workflow_call") && isRecord(cfg) && isRecord(cfg.inputs)) {
      for (const [k, v] of Object.entries(cfg.inputs)) {
        if (isRecord(v) && (v.default === false || v.default === "false" || v.default === undefined)) falsyInputs.add(k.toLowerCase());
      }
      return;
    }
    if (name !== "pull_request" && name !== "push") return;
    if (!isRecord(cfg)) { hasPrOrPushTrigger = true; return; }
    const defaultBranches = new Set(["main", "master", "trunk", "**", "*", ...(defaultBranch ? [defaultBranch] : [])]);
    const badBranches =
      (Array.isArray(cfg["branches-ignore"]) && cfg["branches-ignore"].some((b) => typeof b === "string" && defaultBranches.has(b.trim()))) ||
      (Array.isArray(cfg.branches) && cfg.branches.length > 0 && !cfg.branches.some((b) => typeof b === "string" && defaultBranches.has(b.trim()))) ||
      (name === "push" && Array.isArray(cfg.tags) && cfg.tags.length > 0 && (!Array.isArray(cfg.branches) || cfg.branches.length === 0));
    if (badBranches) return;
    hasPrOrPushTrigger = true;
    if (Array.isArray(cfg["paths-ignore"])) {
      for (const p of cfg["paths-ignore"]) if (typeof p === "string" && !SAFE_DOCS_IGNORE.test(p.trim())) ignoredPaths.push(p.trim());
    }
    if (Array.isArray(cfg.paths)) {
      for (const p of cfg.paths) if (typeof p === "string" && p.trim()) matchedPaths.push(p.trim());
    }
  };
  if (typeof onField === "string") {
    triggers.push(onField); isPrBlocking = isBlockingTriggerConfig(onField, undefined, defaultBranch); collectPaths(onField, undefined);
  } else if (Array.isArray(onField)) {
    for (const item of onField) {
      if (typeof item === "string") { triggers.push(item); if (isBlockingTriggerConfig(item, undefined, defaultBranch)) isPrBlocking = true; collectPaths(item, undefined); }
    }
  } else if (isRecord(onField)) {
    for (const [key, val] of Object.entries(onField)) {
      triggers.push(key); if (isBlockingTriggerConfig(key, val, defaultBranch)) isPrBlocking = true; collectPaths(key, val);
    }
  }
  return { triggers: [...new Set(triggers)], isPrBlocking, ignoredPaths: [...new Set(ignoredPaths)], matchedPaths: [...new Set(matchedPaths)], hasPrOrPushTrigger, falsyInputs };
}

const BAD_ENV_KEY = /^(?:VSTACK_ALLOW_MANIFEST_CHANGE|VSTACK_HOOK_DISABLED|VSTACK_RECEIPT_KEY|NODE_OPTIONS|NODE_PATH|BUN_OPTIONS|BUN_INSTALL|PYTEST_ADDOPTS|PYTEST_PLUGINS|PYTHONSTARTUP|PYTHONPATH|PYTHONUSERBASE|PYTHONHOME|VIRTUAL_ENV|GOFLAGS|GOENV|GOWORK|RUSTFLAGS|RUSTC|RUSTC_WRAPPER|RUSTC_WORKSPACE_WRAPPER|RUSTUP_HOME|CARGO_HOME|CARGO_BUILD_|CARGO_ENCODED_RUSTFLAGS|CARGO_TARGET_|CARGO_ALIAS_|CARGO_ENV_|DOTNET_STARTUP_HOOKS|DOTNET_ADDITIONAL_DEPS|DOTNET_ROOT|DOTNET_CLI_HOME|LD_PRELOAD|DYLD_INSERT_LIBRARIES|PATH|BASH_ENV|ENV|ZDOTDIR|GIT_DIR|GIT_WORK_TREE|GIT_INDEX_FILE|GIT_ATTRIBUTES|GIT_CONFIG(?=$|_))/i;
const BAD_ENV_INLINE = /\b(?:VSTACK_ALLOW_MANIFEST_CHANGE|VSTACK_HOOK_DISABLED|VSTACK_RECEIPT_KEY|NODE_OPTIONS|NODE_PATH|BUN_OPTIONS|BUN_INSTALL|PYTEST_ADDOPTS|PYTEST_PLUGINS|PYTHONSTARTUP|PYTHONPATH|PYTHONUSERBASE|PYTHONHOME|VIRTUAL_ENV|GOFLAGS|GOENV|GOWORK|RUSTFLAGS|RUSTC|RUSTC_WRAPPER|RUSTC_WORKSPACE_WRAPPER|RUSTUP_HOME|CARGO_HOME|CARGO_BUILD_|CARGO_ENCODED_RUSTFLAGS|CARGO_TARGET_|CARGO_ALIAS_|CARGO_ENV_|DOTNET_STARTUP_HOOKS|DOTNET_ADDITIONAL_DEPS|DOTNET_ROOT|DOTNET_CLI_HOME|LD_PRELOAD|DYLD_INSERT_LIBRARIES|PATH|BASH_ENV|ENV|ZDOTDIR|GIT_DIR|GIT_WORK_TREE|GIT_INDEX_FILE|GIT_ATTRIBUTES|GIT_CONFIG(?:_[A-Z0-9_]+)?)\s*=/i;
const SAFE_GOFLAGS = /^(?:\s*-(?:tags=[A-Za-z0-9_,.-]+|race|mod=readonly|count=1|trimpath|v))+\s*$/;
const SAFE_GIT_AUTH_KEY = /^url\.https:\/\/x-access-token:\$\{\{\s*(?:github\.token|secrets\.[A-Z0-9_]+)\s*\}\}@github\.com\/\.insteadOf$/i;

function isPoisoningGithubEnv(runText: string): boolean {
  if (/\bGITHUB_PATH\b/i.test(runText)) return true;
  if (!/\bGITHUB_ENV\b/i.test(runText)) return false;
  return BAD_ENV_INLINE.test(runText) || /\b(?:eval|base64|xxd)\b|\$[A-Za-z_]\w*=/.test(runText);
}

function isBenignGitAuthEnv(envObj: Record<string, unknown>): boolean {
  return String(envObj.GIT_CONFIG_COUNT ?? "").trim() === "1" && typeof envObj.GIT_CONFIG_KEY_0 === "string" && SAFE_GIT_AUTH_KEY.test(envObj.GIT_CONFIG_KEY_0.trim()) && typeof envObj.GIT_CONFIG_VALUE_0 === "string" && envObj.GIT_CONFIG_VALUE_0.trim() === "https://github.com/";
}

function hasPoisonedEnv(envObj: unknown): boolean {
  return isRecord(envObj) && Object.entries(envObj).some(([k, v]) => {
    if (!BAD_ENV_KEY.test(k)) return false;
    if (/^GOFLAGS$/i.test(k) && typeof v === "string" && SAFE_GOFLAGS.test(v)) return false;
    if (/^GIT_CONFIG_(?:COUNT|KEY_0|VALUE_0)$/i.test(k) && isBenignGitAuthEnv(envObj)) return false;
    return true;
  });
}

function extractSafeEnvLiterals(envObj: unknown): Map<string, string> {
  const out = new Map<string, string>();
  if (!isRecord(envObj)) return out;
  for (const [k, v] of Object.entries(envObj)) {
    if (typeof v === "string" && !BAD_ENV_KEY.test(k) && /^[A-Za-z0-9_./:${}\s-]+$/.test(v.trim())) out.set(k, v.trim());
  }
  return out;
}

function expandSafeEnv(runText: string, envMap: ReadonlyMap<string, string>): string {
  return runText
    .replace(/\$\{\{\s*env\.([A-Za-z_][A-Za-z0-9_]*)\s*\}\}/g, (m, key: string) => envMap.get(key) ?? m)
    .replace(/\$\{env:([A-Za-z_][A-Za-z0-9_]*)\}/g, (m, key: string) => envMap.get(key) ?? m);
}

function knownActionCommands(step: Record<string, unknown>, envMap: ReadonlyMap<string, string>): string[] {
  if (typeof step.uses !== "string") return [];
  const uses = step.uses.trim().split("@")[0]?.toLowerCase() ?? "";
  if (uses === "golangci/golangci-lint-action") return ["golangci-lint run"];
  if (uses === "golang/govulncheck-action") return ["govulncheck"];
  if (uses === "astral-sh/ruff-action") return ["ruff check"];
  if (uses === "actions-rs/clippy-check") return ["cargo clippy"];
  if (uses === "codspeedhq/action" && isRecord(step.with) && typeof step.with.run === "string") return ["codspeed", ...sanitizeShellBlock(expandSafeEnv(step.with.run, envMap))];
  return [];
}

function isLocalActionSafe(usesVal: string, filesByRel?: ReadonlyMap<string, ScannedFile>): boolean {
  if (!filesByRel || filesByRel.size === 0) return false;
  const queue: Array<{ uses: string; depth: number }> = [{ uses: usesVal, depth: 0 }];
  while (queue.length > 0) {
    const cur = queue.pop();
    if (!cur || cur.depth > 2) return false;
    const base = cur.uses.trim().replace(/^\.\//, "").replace(/\/+$/, "");
    const actionFile = filesByRel.get(`${base}/action.yml`) ?? filesByRel.get(`${base}/action.yaml`) ?? filesByRel.get(base);
    if (!actionFile) return false;
    let aDoc: unknown;
    try { aDoc = YAML.parse(actionFile.content); } catch { return false; }
    if (!isRecord(aDoc) || !isRecord(aDoc.runs) || !Array.isArray(aDoc.runs.steps)) return false;
    for (const s of aDoc.runs.steps) {
      if (!isRecord(s)) continue;
      if (hasPoisonedEnv(s.env) || (typeof s.run === "string" && isPoisoningGithubEnv(s.run))) return false;
      if (typeof s.uses === "string" && s.uses.trim().startsWith("./")) queue.push({ uses: s.uses, depth: cur.depth + 1 });
    }
  }
  return true;
}

function computeDeadAndDeployJobs(rawJobs: Record<string, unknown>, falsyInputs: ReadonlySet<string>): { deadJobSet: Set<string>; deployJobSet: Set<string> } {
  const deadJobSet = new Set<string>();
  const deployJobSet = new Set<string>();
  for (const [jobId, jobVal] of Object.entries(rawJobs)) {
    if (!isRecord(jobVal)) continue;
    if (isMainPushDeployIf(jobVal.if) && !isContinueOnError(jobVal["continue-on-error"])) { deployJobSet.add(jobId); deadJobSet.add(jobId); continue; }
    if (!isUnconditionalIf(jobVal.if, falsyInputs) || isContinueOnError(jobVal["continue-on-error"])) deadJobSet.add(jobId);
  }
  let changed = true;
  while (changed) {
    changed = false;
    for (const [jobId, jobVal] of Object.entries(rawJobs)) {
      if (deadJobSet.has(jobId) || !isRecord(jobVal)) continue;
      const needs = jobVal.needs;
      const depList = typeof needs === "string" ? [needs] : Array.isArray(needs) ? needs.filter((n): n is string => typeof n === "string") : [];
      if (depList.some((dep) => deadJobSet.has(dep))) { deadJobSet.add(jobId); changed = true; }
    }
  }
  return { deadJobSet, deployJobSet };
}

function collectJobStepCommands(
  jobVal: Record<string, unknown>,
  ctx: { wfEnvMap: Map<string, string>; wfDefaults: unknown; wfWorkDir: unknown; filesByRel?: ReadonlyMap<string, ScannedFile>; isDeployJob: boolean; activeCommands: string[]; scopedCommands: Array<{ cwd: string; command: string }>; deployCommands: string[] },
): void {
  const jobEnvMap = new Map(ctx.wfEnvMap);
  for (const [k, v] of extractSafeEnvLiterals(jobVal.env)) jobEnvMap.set(k, v);
  const jobShell = isRecord(jobVal.defaults) && isRecord(jobVal.defaults.run) ? jobVal.defaults.run.shell : ctx.wfDefaults;
  const jobWorkDir = isRecord(jobVal.defaults) && isRecord(jobVal.defaults.run) ? jobVal.defaults.run["working-directory"] : ctx.wfWorkDir;
  const rawSteps = Array.isArray(jobVal.steps) ? jobVal.steps : [];
  const steps = rawSteps.flatMap((s) => (isRecord(s) && Array.isArray(s.parallel) ? s.parallel : [s]));
  let jobEnvPoisoned = false;
  for (const step of steps) {
    if (!isRecord(step)) continue;
    if (typeof step.uses === "string" && step.uses.trim().startsWith("./") && !isLocalActionSafe(step.uses, ctx.filesByRel)) { jobEnvPoisoned = true; continue; }
    if (typeof step.run === "string" && isPoisoningGithubEnv(step.run)) { jobEnvPoisoned = true; continue; }
    if (jobEnvPoisoned || hasPoisonedEnv(step.env) || !isUnconditionalIf(step.if) || isContinueOnError(step["continue-on-error"]) || !isAllowedShell(step.shell ?? jobShell)) continue;
    const rawWd = step["working-directory"] ?? jobWorkDir;
    const cwd = typeof rawWd === "string" ? rawWd.trim().replace(/^\.\/+/, "").replace(/\/+$/, "") : "";
    if (cwd.startsWith("/") || cwd.includes("..")) continue;
    const stepEnvMap = new Map(jobEnvMap);
    for (const [k, v] of extractSafeEnvLiterals(step.env)) stepEnvMap.set(k, v);
    const stepCmds: string[] = knownActionCommands(step, stepEnvMap);
    if (typeof step.run === "string") stepCmds.push(...sanitizeShellBlock(expandSafeEnv(step.run, stepEnvMap)));
    for (const cmd of stepCmds) {
      if (ctx.isDeployJob) ctx.deployCommands.push(cmd);
      else { ctx.activeCommands.push(cmd); ctx.scopedCommands.push({ cwd: cwd === "." ? "" : cwd, command: cmd }); }
    }
  }
}

interface WorkflowFrame { wfFile: ScannedFile; doc: Record<string, unknown>; forceDeploy: boolean; depth: number; visited: ReadonlySet<string>; }

function enqueueReusableWorkflow(
  usesStr: string,
  frame: WorkflowFrame,
  isDeployJob: boolean,
  ctx: { filesByRel?: ReadonlyMap<string, ScannedFile>; stack: WorkflowFrame[] },
): void {
  if (frame.depth >= 4 || !ctx.filesByRel) return;
  const rawRef = usesStr.trim().replace(/^\$\//, "").replace(/^\.\//, "").split("@")[0] ?? "";
  const nextVisited = new Set(frame.visited); nextVisited.add(frame.wfFile.rel);
  const callee = rawRef.startsWith(".github/workflows/") && !nextVisited.has(rawRef) ? ctx.filesByRel.get(rawRef) : undefined;
  if (!callee) return;
  try {
    const calleeDoc = YAML.parse(callee.content);
    if (isRecord(calleeDoc)) ctx.stack.push({ wfFile: callee, doc: calleeDoc, forceDeploy: isDeployJob, depth: frame.depth + 1, visited: nextVisited });
  } catch { void 0; }
}

export function parseGitHubWorkflow(file: ScannedFile, allFiles?: readonly ScannedFile[], defaultBranch?: string): ActiveWorkflowInfo {
  if (!file.rel) throw new Error("Workflow ScannedFile must have rel.");
  let rootDoc: unknown;
  try { rootDoc = YAML.parse(file.content); } catch { return { file: file.rel, isPrBlocking: false, triggers: [], activeCommands: [], deadJobs: ["<invalid-yaml>"] }; }
  if (!isRecord(rootDoc)) return { file: file.rel, isPrBlocking: false, triggers: [], activeCommands: [], deadJobs: [] };

  const filesByRel = allFiles ? new Map(allFiles.map((f) => [f.rel, f])) : undefined;
  const rootTriggers = extractTriggers(rootDoc.on ?? rootDoc.true, defaultBranch);
  const rootRawJobs = isRecord(rootDoc.jobs) ? rootDoc.jobs : {};
  const rootJobs = computeDeadAndDeployJobs(rootRawJobs, rootTriggers.falsyInputs);
  const activeCommands: string[] = [];
  const scopedCommands: Array<{ cwd: string; command: string }> = [];
  const deployCommands: string[] = [];
  const stack: WorkflowFrame[] = [{ wfFile: file, doc: rootDoc, forceDeploy: false, depth: 0, visited: new Set() }];

  while (stack.length > 0) {
    const frame = stack.pop();
    if (!frame || hasPoisonedEnv(frame.doc.env)) continue;
    const { doc, wfFile, forceDeploy } = frame;
    const tr = wfFile === file ? rootTriggers : extractTriggers(doc.on ?? doc.true, defaultBranch);
    const rawJobs = isRecord(doc.jobs) ? doc.jobs : {};
    const { deadJobSet, deployJobSet } = wfFile === file ? rootJobs : computeDeadAndDeployJobs(rawJobs, tr.falsyInputs);
    const wfDefaults = isRecord(doc.defaults) && isRecord(doc.defaults.run) ? doc.defaults.run.shell : undefined;
    const wfWorkDir = isRecord(doc.defaults) && isRecord(doc.defaults.run) ? doc.defaults.run["working-directory"] : undefined;
    const wfEnvMap = extractSafeEnvLiterals(doc.env);
    for (const [jobId, jobVal] of Object.entries(rawJobs)) {
      const isDeployJob = forceDeploy || deployJobSet.has(jobId);
      if ((deadJobSet.has(jobId) && !deployJobSet.has(jobId)) || !isRecord(jobVal) || hasPoisonedEnv(jobVal.env)) continue;
      if (typeof jobVal.uses === "string") { enqueueReusableWorkflow(jobVal.uses, frame, isDeployJob, { filesByRel, stack }); continue; }
      collectJobStepCommands(jobVal, { wfEnvMap, wfDefaults, wfWorkDir, filesByRel, isDeployJob, activeCommands, scopedCommands, deployCommands });
    }
  }

  return {
    file: file.rel, isPrBlocking: rootTriggers.isPrBlocking, triggers: rootTriggers.triggers, activeCommands, scopedCommands,
    ...(deployCommands.length > 0 ? { deployCommands } : {}),
    ...(rootTriggers.ignoredPaths.length > 0 ? { ignoredPaths: rootTriggers.ignoredPaths } : {}),
    ...(rootTriggers.matchedPaths.length > 0 ? { matchedPaths: rootTriggers.matchedPaths } : {}),
    hasPrOrPushTrigger: rootTriggers.hasPrOrPushTrigger, deadJobs: [...rootJobs.deadJobSet].sort(),
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
  checked: boolean; passed: boolean; requiredChecks: string[]; codeOwnerReviewsRequired: boolean; adminsEnforced: boolean; detail: string;
} {
  const remote = runGitClean(repoRoot, ["remote", "get-url", "origin"]);
  const match = /github\.com[:/]([^/]+\/[^/]+?)(?:\.git)?$/i.exec((remote.stdout ?? "").trim());
  if (!match?.[1]) {
    return { checked: false, passed: false, requiredChecks: [], codeOwnerReviewsRequired: false, adminsEnforced: false, detail: "No GitHub origin remote detected." };
  }
  const slug = match[1];
  const repoInfo = spawnSync("gh", ["api", `repos/${slug}`, "--jq", ".default_branch"], { encoding: "utf8", timeout: 10_000 });
  const defaultBranch = repoInfo.status === 0 && repoInfo.stdout.trim() ? repoInfo.stdout.trim() : "main";
  const api = spawnSync("gh", ["api", `repos/${slug}/branches/${defaultBranch}/protection`], { encoding: "utf8", timeout: 10_000 });
  if (api.status !== 0) {
    const stderr = (api.stderr ?? api.stdout ?? "").trim();
    const isUnprotected = /404|Branch not protected/i.test(stderr);
    return {
      checked: isUnprotected, passed: false, requiredChecks: [], codeOwnerReviewsRequired: false, adminsEnforced: false,
      detail: isUnprotected ? `Branch '${defaultBranch}' on ${slug} is NOT protected (HTTP 404).` : `Unable to read branch protection for ${slug}/${defaultBranch}: ${stderr.slice(0, 140)}`,
    };
  }
  return evaluateBranchProtectionJson(defaultBranch, api.stdout);
}

export function evaluateBranchProtectionJson(defaultBranch: string, rawJson: string): {
  checked: boolean; passed: boolean; requiredChecks: string[]; codeOwnerReviewsRequired: boolean; adminsEnforced: boolean; detail: string;
} {
  if (!defaultBranch || !rawJson) return { checked: false, passed: false, requiredChecks: [], codeOwnerReviewsRequired: false, adminsEnforced: false, detail: "Missing branch protection JSON." };
  try {
    const parsed = JSON.parse(rawJson) as {
      required_status_checks?: { contexts?: string[]; checks?: Array<{ context?: string }> };
      required_pull_request_reviews?: { require_code_owner_reviews?: boolean; required_approving_review_count?: number; dismiss_stale_reviews?: boolean };
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
    const passed = checks.length > 0 && hasVeristack && codeOwnerReviewsRequired && hasApprovals && dismissStale && adminsEnforced && noForcePush;
    return {
      checked: true, passed, requiredChecks: [...new Set(checks)], codeOwnerReviewsRequired, adminsEnforced,
      detail: passed
        ? `Branch '${defaultBranch}' enforces strict Veristack check, CODEOWNERS reviews (>=1, dismiss stale), admins, and blocks force-push.`
        : `Incomplete protection on '${defaultBranch}': veristackCheck=${hasVeristack}, codeOwnerReviews=${codeOwnerReviewsRequired}, approvals>=1=${hasApprovals}, dismissStale=${dismissStale}, enforceAdmins=${adminsEnforced}, noForcePush=${noForcePush}.`,
    };
  } catch {
    return { checked: false, passed: false, requiredChecks: [], codeOwnerReviewsRequired: false, adminsEnforced: false, detail: "Failed to parse branch protection JSON." };
  }
}
