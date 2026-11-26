import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { scanGitDiffCheats } from "../ci-auditor.ts";
import type { Finding } from "../types.ts";
import { type CheckFileTier, scanSingleFile } from "./check-file.ts";

export type HookEventKind = "post-edit" | "pre-edit" | "stop";
export type HookHarness = "claude" | "codex" | "cursor" | "copilot" | "grok";

export interface HookProjectConfig {
  enabled: boolean;
  tier: CheckFileTier;
  auditLog?: string;
  harnesses: HookHarness[];
}

interface SessionState {
  touchedFiles: string[];
  reportedKeys: string[];
}

export interface HookExecutionResult {
  exitCode: number;
  stdout: string;
  findings: Finding[];
}

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

export function loadHookConfig(repoRoot: string): HookProjectConfig {
  const cfgPath = path.join(repoRoot, ".verification", "hooks.json");
  const defaults: HookProjectConfig = { enabled: true, tier: "immediate", harnesses: [] };
  if (!fs.existsSync(cfgPath)) return defaults;
  try {
    const parsed: unknown = JSON.parse(fs.readFileSync(cfgPath, "utf8"));
    if (!isRecord(parsed)) return defaults;
    return {
      enabled: typeof parsed.enabled === "boolean" ? parsed.enabled : true,
      tier: parsed.tier === "all" ? "all" : "immediate",
      auditLog: typeof parsed.auditLog === "string" && parsed.auditLog.trim() ? parsed.auditLog.trim() : undefined,
      harnesses: Array.isArray(parsed.harnesses)
        ? parsed.harnesses.filter((h): h is HookHarness =>
            h === "claude" || h === "codex" || h === "cursor" || h === "copilot" || h === "grok",
          )
        : [],
    };
  } catch {
    return defaults;
  }
}

function sessionStatePath(repoRoot: string, sessionId: string): string {
  const hash = crypto.createHash("sha256").update(`${repoRoot}:${sessionId}`).digest("hex").slice(0, 16);
  return path.join(os.tmpdir(), "vstack-hook-sessions", `${hash}.json`);
}

function readSessionState(statePath: string): SessionState {
  try {
    const parsed: unknown = JSON.parse(fs.readFileSync(statePath, "utf8"));
    if (!isRecord(parsed)) return { touchedFiles: [], reportedKeys: [] };
    return {
      touchedFiles: Array.isArray(parsed.touchedFiles) ? parsed.touchedFiles.filter((x): x is string => typeof x === "string") : [],
      reportedKeys: Array.isArray(parsed.reportedKeys) ? parsed.reportedKeys.filter((x): x is string => typeof x === "string") : [],
    };
  } catch {
    return { touchedFiles: [], reportedKeys: [] };
  }
}

function writeSessionState(statePath: string, state: SessionState): void {
  fs.mkdirSync(path.dirname(statePath), { recursive: true });
  fs.writeFileSync(statePath, `${JSON.stringify(state)}\n`, "utf8");
}

function appendAuditLog(repoRoot: string, auditLogPath: string | undefined, entry: Record<string, unknown>): void {
  const target = process.env.VSTACK_HOOK_LOG || auditLogPath;
  if (!target) return;
  const abs = path.isAbsolute(target) ? target : path.resolve(repoRoot, target);
  try {
    fs.mkdirSync(path.dirname(abs), { recursive: true });
    fs.appendFileSync(abs, `${JSON.stringify({ ts: new Date().toISOString(), ...entry })}\n`, "utf8");
  } catch {
    return;
  }
}

function extractEditedPaths(payload: Record<string, unknown>): string[] {
  const paths: string[] = [];
  const toolInput = isRecord(payload.tool_input) ? payload.tool_input : payload;
  for (const key of ["file_path", "filePath", "path", "target_file", "targetFile"]) {
    const val = toolInput[key];
    if (typeof val === "string" && val.trim()) paths.push(val.trim());
  }
  if (typeof toolInput.patch === "string") {
    for (const m of toolInput.patch.matchAll(/^\*\*\*\s+(?:Update|Add)\s+File:\s+(.+)$/gm)) {
      if (m[1]) paths.push(m[1].trim());
    }
  }
  return [...new Set(paths)];
}

const PROTECTED_CONTROL_PLANE =
  /^(?:\.?vstack\.json|\.vstackignore|bunfig\.toml|\.verification\/(?:rungs|vstack|hooks|control-plan|invariants|behavior-changes|chokepoints)\.json|\.verification\/receipts\/|\.github\/CODEOWNERS$|CODEOWNERS$)/i;

function extractProposedContent(payload: Record<string, unknown>, absFilePath: string): string | undefined {
  const toolInput = isRecord(payload.tool_input) ? payload.tool_input : payload;
  for (const key of ["content", "contents", "new_content", "file_text"]) {
    if (typeof toolInput[key] === "string") return toolInput[key];
  }
  const oldStr = typeof toolInput.old_string === "string" ? toolInput.old_string : typeof toolInput.oldString === "string" ? toolInput.oldString : undefined;
  const newStr = typeof toolInput.new_string === "string" ? toolInput.new_string : typeof toolInput.newString === "string" ? toolInput.newString : undefined;
  if (oldStr !== undefined && newStr !== undefined && fs.existsSync(absFilePath)) {
    const existing = fs.readFileSync(absFilePath, "utf8");
    if (existing.includes(oldStr)) {
      return toolInput.replace_all === true ? existing.split(oldStr).join(newStr) : existing.replace(oldStr, newStr);
    }
  }
  return undefined;
}

function formatReminder(header: string, findings: readonly Finding[]): string {
  const lines = [header];
  for (const f of findings.slice(0, 10)) {
    lines.push(`- [${f.severity.toUpperCase()}] ${f.rule} ${f.file}:${f.line} — ${f.message} Fix: ${f.fix}`);
  }
  if (findings.length > 10) {
    lines.push(`... and ${findings.length - 10} more finding(s).`);
  }
  lines.push("Fix the code directly; never disable rules, weaken configs, or add suppressions.");
  return lines.join("\n");
}

function findingKey(f: Finding): string {
  return `${f.rule}:${f.file}:${f.line}`;
}

export function executeHookEvent(
  event: HookEventKind,
  rawStdin: string,
  options: { repoRoot?: string; harness?: HookHarness; tier?: CheckFileTier } = {},
): HookExecutionResult {
  if (process.env.VSTACK_HOOK_DISABLED === "1") {
    return { exitCode: 0, stdout: "", findings: [] };
  }

  let payload: Record<string, unknown> = {};
  if (rawStdin.trim()) {
    try {
      const parsed: unknown = JSON.parse(rawStdin);
      if (isRecord(parsed)) payload = parsed;
    } catch {
      return { exitCode: 0, stdout: "", findings: [] };
    }
  }

  const cwd = typeof payload.cwd === "string" && payload.cwd.trim() ? payload.cwd.trim() : (options.repoRoot ?? process.cwd());
  const repoRoot = path.resolve(cwd);
  const config = loadHookConfig(repoRoot);
  if (!config.enabled) {
    return { exitCode: 0, stdout: "", findings: [] };
  }

  const harness: HookHarness = options.harness ?? "claude";
  const tier: CheckFileTier = options.tier ?? (harness === "copilot" ? "all" : config.tier);
  const sessionId = typeof payload.session_id === "string" && payload.session_id.trim() ? payload.session_id.trim() : "default";
  const statePath = sessionStatePath(repoRoot, sessionId);

  if (event === "pre-edit") {
    const edited = extractEditedPaths(payload);
    const findings: Finding[] = [];
    for (const filePath of edited) {
      const abs = path.isAbsolute(filePath) ? path.resolve(filePath) : path.resolve(repoRoot, filePath);
      const rel = path.relative(repoRoot, abs).split(path.sep).join("/");
      if (PROTECTED_CONTROL_PLANE.test(rel)) {
        findings.push({
          id: `HOOK:protected:${rel}`,
          rule: "hook-protected-control-plane",
          category: "cheat",
          rung: "R0",
          severity: "error",
          file: rel,
          line: 1,
          message: `Direct agent edit to verification control-plane file '${rel}' is blocked by pre-edit policy.`,
          fix: "Fix the underlying code defect instead of weakening verification configs, manifests, receipts, or hooks.",
        });
        continue;
      }
      const proposed = extractProposedContent(payload, abs);
      if (proposed === undefined && !fs.existsSync(abs)) continue;
      const res = scanSingleFile(filePath, { repoRoot, tier: "immediate", content: proposed, strict: true });
      findings.push(...res.findings);
    }
    appendAuditLog(repoRoot, config.auditLog, { event, harness, files: edited, findings: findings.length });
    if (findings.length === 0) {
      return { exitCode: 0, stdout: JSON.stringify({ permission: "allow" }), findings: [] };
    }
    const msg = formatReminder(`Veristack blocked write (${findings.length} immediate slop/cheat violation(s)):`, findings);
    return {
      exitCode: 0,
      stdout: JSON.stringify({
        permission: "deny",
        user_message: `Veristack blocked write with ${findings.length} violation(s).`,
        agent_message: msg,
      }),
      findings,
    };
  }

  if (event === "post-edit") {
    const edited = extractEditedPaths(payload);
    if (edited.length === 0) return { exitCode: 0, stdout: "", findings: [] };

    const state = readSessionState(statePath);
    const touchedSet = new Set(state.touchedFiles);
    const reportedSet = new Set(state.reportedKeys);
    const findings: Finding[] = [];

    for (const filePath of edited) {
      const abs = path.isAbsolute(filePath) ? path.resolve(filePath) : path.resolve(repoRoot, filePath);
      if (!fs.existsSync(abs)) continue;
      const res = scanSingleFile(filePath, { repoRoot, tier, strict: true });
      if (res.language) touchedSet.add(res.file);
      for (const f of res.findings) {
        findings.push(f);
        reportedSet.add(findingKey(f));
      }
    }

    writeSessionState(statePath, { touchedFiles: [...touchedSet], reportedKeys: [...reportedSet] });
    appendAuditLog(repoRoot, config.auditLog, { event, harness, files: edited, findings: findings.length });

    if (findings.length === 0 || harness === "grok") {
      return { exitCode: 0, stdout: "", findings };
    }

    const msg = formatReminder(`Veristack detected ${findings.length} issue(s) on your edit — fix before continuing:`, findings);
    return {
      exitCode: 0,
      stdout: JSON.stringify({
        hookSpecificOutput: {
          hookEventName: "PostToolUse",
          additionalContext: msg,
        },
      }),
      findings,
    };
  }

  if (payload.reason === "shutdown") {
    return { exitCode: 0, stdout: "", findings: [] };
  }

  const state = readSessionState(statePath);
  const findings: Finding[] = [];

  for (const rel of state.touchedFiles) {
    const abs = path.resolve(repoRoot, rel);
    if (!fs.existsSync(abs)) continue;
    const res = scanSingleFile(rel, { repoRoot, tier: "all", strict: true });
    for (const f of res.findings) {
      findings.push(f);
    }
  }

  for (const cheat of scanGitDiffCheats(repoRoot, "HEAD")) {
    findings.push(cheat);
  }

  try {
    if (fs.existsSync(statePath)) fs.unlinkSync(statePath);
  } catch {
    void 0;
  }

  appendAuditLog(repoRoot, config.auditLog, { event, harness, touched: state.touchedFiles.length, findings: findings.length });

  if (findings.length === 0) {
    return { exitCode: 0, stdout: "", findings: [] };
  }

  const msg = formatReminder(`Veristack deep stop-pass found ${findings.length} unaddressed issue(s):`, findings);
  if (harness === "grok") {
    return { exitCode: 0, stdout: JSON.stringify({ additionalContext: msg }), findings };
  }
  if (payload.stop_hook_active === true) {
    return { exitCode: 0, stdout: "", findings };
  }
  return {
    exitCode: 0,
    stdout: JSON.stringify({ decision: "block", reason: msg }),
    findings,
  };
}
