import { spawnSync } from "node:child_process";
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

const NON_BLOCKING_ONLY_TRIGGERS = new Set(["workflow_dispatch", "schedule", "repository_dispatch", "workflow_call"]);
const PR_BLOCKING_TRIGGERS = new Set(["pull_request", "pull_request_target", "merge_group", "push"]);

function stripYamlComment(line: string): string {
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

function isFalseCondition(expr: string): boolean {
  const norm = expr.trim().replace(/^\$\{\{\s*|\s*\}\}$/g, "").trim().toLowerCase();
  return norm === "false" || norm === "0" || norm === "!true" || /\b&&\s*false\b/.test(norm);
}

function sanitizeShellCommandLine(rawLine: string): string {
  const trimmed = stripYamlComment(rawLine).trim();
  if (!trimmed) return "";
  if (/^(?:echo|printf|true|:)\b/.test(trimmed)) return "";
  if (/\|\|\s*(?:true|:)\s*$/.test(trimmed)) return "";
  return trimmed;
}

function parseTriggers(lines: readonly string[]): string[] {
  const triggers: string[] = [];
  let inOnBlock = false;
  let onIndent = -1;

  for (const raw of lines) {
    const clean = stripYamlComment(raw);
    if (!clean.trim()) continue;
    const indent = clean.length - clean.trimStart().length;
    const trimmed = clean.trim();

    if (indent === 0 && /^on\s*:/.test(trimmed)) {
      const rest = trimmed.replace(/^on\s*:/, "").trim();
      if (rest) {
        const inline = rest.replace(/^\[|\]$/g, "").split(",").map((s) => s.trim().replace(/^['"]|['"]$/g, ""));
        for (const t of inline) if (t) triggers.push(t);
        inOnBlock = false;
      } else {
        inOnBlock = true;
        onIndent = indent;
      }
      continue;
    }

    if (inOnBlock) {
      if (indent <= onIndent) {
        inOnBlock = false;
        continue;
      }
      const keyMatch = /^(?:-\s*)?([a-zA-Z0-9_-]+)\s*:?/.exec(trimmed);
      if (keyMatch?.[1] && (indent === 2 || trimmed.startsWith("-"))) {
        triggers.push(keyMatch[1]);
      }
    }
  }
  return [...new Set(triggers)];
}

export function parseGitHubWorkflow(file: ScannedFile): ActiveWorkflowInfo {
  const lines = file.content.split(/\r?\n/);
  const triggers = parseTriggers(lines);
  const isPrBlocking =
    triggers.some((t) => PR_BLOCKING_TRIGGERS.has(t)) &&
    !triggers.every((t) => NON_BLOCKING_ONLY_TRIGGERS.has(t));

  const activeCommands: string[] = [];
  const deadJobs: string[] = [];

  let inJobs = false;
  let jobIndent = -1;
  let currentJob = "";
  let currentJobDead = false;
  let stepIndent = -1;
  let currentStepDead = false;
  let inRunBlock = false;
  let runIndent = -1;

  for (const raw of lines) {
    const clean = stripYamlComment(raw);
    const trimmed = clean.trim();
    const indent = clean.length - clean.trimStart().length;

    if (inRunBlock) {
      if (!trimmed) continue;
      if (indent > runIndent) {
        if (!currentJobDead && !currentStepDead) {
          const cmd = sanitizeShellCommandLine(raw);
          if (cmd) activeCommands.push(cmd);
        }
        continue;
      }
      inRunBlock = false;
    }

    if (!trimmed) continue;

    if (indent === 0) {
      inJobs = /^jobs\s*:/.test(trimmed);
      jobIndent = -1;
      currentJob = "";
      currentJobDead = false;
      continue;
    }

    if (!inJobs) continue;

    if (jobIndent < 0 || indent === jobIndent) {
      const m = /^([a-zA-Z0-9_-]+)\s*:/.exec(trimmed);
      if (m?.[1]) {
        jobIndent = indent;
        currentJob = m[1];
        currentJobDead = false;
        stepIndent = -1;
        currentStepDead = false;
        continue;
      }
    }

    if (indent > jobIndent && stepIndent < 0) {
      if (/^if\s*:/.test(trimmed)) {
        const expr = trimmed.replace(/^if\s*:/, "");
        if (isFalseCondition(expr)) {
          currentJobDead = true;
          deadJobs.push(currentJob);
        }
      } else if (/^continue-on-error\s*:\s*true\b/i.test(trimmed)) {
        currentJobDead = true;
        deadJobs.push(currentJob);
      } else if (/^steps\s*:/.test(trimmed)) {
        stepIndent = indent;
      }
      continue;
    }

    if (stepIndent >= 0 && indent > stepIndent) {
      if (trimmed.startsWith("-")) {
        currentStepDead = false;
        const afterDash = trimmed.slice(1).trim();
        if (/^if\s*:/.test(afterDash) && isFalseCondition(afterDash.replace(/^if\s*:/, ""))) {
          currentStepDead = true;
        } else if (/^continue-on-error\s*:\s*true\b/i.test(afterDash)) {
          currentStepDead = true;
        } else if (/^run\s*:/.test(afterDash)) {
          const val = afterDash.replace(/^run\s*:/, "").trim();
          if (val === "|" || val === ">" || val === "|-" || val === ">-") {
            inRunBlock = true;
            runIndent = indent;
          } else if (!currentJobDead && !currentStepDead) {
            const cmd = sanitizeShellCommandLine(val);
            if (cmd) activeCommands.push(cmd);
          }
        }
        continue;
      }

      if (/^if\s*:/.test(trimmed) && isFalseCondition(trimmed.replace(/^if\s*:/, ""))) {
        currentStepDead = true;
      } else if (/^continue-on-error\s*:\s*true\b/i.test(trimmed)) {
        currentStepDead = true;
      } else if (/^run\s*:/.test(trimmed)) {
        const val = trimmed.replace(/^run\s*:/, "").trim();
        if (val === "|" || val === ">" || val === "|-" || val === ">-") {
          inRunBlock = true;
          runIndent = indent;
        } else if (!currentJobDead && !currentStepDead) {
          const cmd = sanitizeShellCommandLine(val);
          if (cmd) activeCommands.push(cmd);
        }
      }
    }
  }

  return { file: file.rel, isPrBlocking, triggers, activeCommands, deadJobs };
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
  const coFile = files.find((f) => /(?:^|\/)codeowners$/i.test(f.rel));
  if (!coFile) {
    return { hasFile: false, uncoveredSurfaces: ["CODEOWNERS"], passed: false };
  }

  const patterns: string[] = [];
  for (const raw of coFile.content.split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || line.startsWith("#")) continue;
    const parts = line.split(/\s+/);
    const pat = parts[0] ?? "";
    const owners = parts.slice(1).filter((p) => p.startsWith("@") || p.includes("@"));
    if (pat && owners.length > 0) patterns.push(pat);
  }

  if (patterns.length === 0) {
    return { hasFile: true, file: coFile.rel, uncoveredSurfaces: ["CODEOWNERS has zero valid owner rules"], passed: false };
  }

  const allSet = new Set(allRelPaths);
  const surfaces = [".github/workflows/ci.yml", ".verification/rungs.json", coFile.rel];
  if (allSet.has(".vstackignore")) surfaces.push(".vstackignore");
  if (allSet.has(".vstack.json")) surfaces.push(".vstack.json");
  if (allSet.has("lefthook.yml")) surfaces.push("lefthook.yml");
  if (allSet.has(".verification/control-plan.json")) surfaces.push(".verification/control-plan.json");
  if (allSet.has(".verification/escapes.json")) surfaces.push(".verification/escapes.json");

  const uncovered = surfaces.filter((surf) => !patterns.some((pat) => globMatchesPath(pat, surf)));
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
  detail: string;
} {
  const remote = spawnSync("git", ["-C", repoRoot, "remote", "get-url", "origin"], { encoding: "utf8" });
  const match = /github\.com[:/]([^/]+\/[^/.]+)(?:\.git)?$/i.exec((remote.stdout ?? "").trim());
  if (!match?.[1]) {
    return { checked: false, passed: false, requiredChecks: [], detail: "No GitHub origin remote detected." };
  }
  const slug = match[1];
  const api = spawnSync("gh", ["api", `repos/${slug}/branches/main/protection`], {
    encoding: "utf8",
    timeout: 10_000,
  });
  if (api.status !== 0) {
    return {
      checked: false,
      passed: false,
      requiredChecks: [],
      detail: `Unable to read branch protection for ${slug}/main via gh api.`,
    };
  }
  try {
    const parsed = JSON.parse(api.stdout) as {
      required_status_checks?: { contexts?: string[]; checks?: Array<{ context?: string }> };
    };
    const checks = [
      ...(parsed.required_status_checks?.contexts ?? []),
      ...(parsed.required_status_checks?.checks?.map((c) => c.context ?? "").filter(Boolean) ?? []),
    ];
    const hasVeristack = checks.some((c) => /veristack|vstack|strict/i.test(c));
    return {
      checked: true,
      passed: checks.length > 0 && hasVeristack,
      requiredChecks: [...new Set(checks)],
      detail: hasVeristack
        ? `Required status checks enforce Veristack (${checks.join(", ")}).`
        : `Branch protection has ${checks.length} required check(s), none matching Veristack.`,
    };
  } catch {
    return { checked: false, passed: false, requiredChecks: [], detail: "Failed to parse branch protection JSON." };
  }
}
