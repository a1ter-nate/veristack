import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { hasPathologicalNesting } from "../ast/ts-ast.ts";
import { scanGitDiffCheats } from "../ci-auditor.ts";
import { runGitClean } from "../rungs/config-audit.ts";
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
  stderr?: string;
  findings: Finding[];
}

const PROTECTED_CONTROL_PLANE =
  /(?:^|\/)(?:\.?vstack\.json|\.vstackignore|\.gitignore|\.gitattributes|\.npmrc|\.mcp\.json|Makefile|bun\.lock|package-lock\.json|pnpm-lock\.yaml|yarn\.lock|Cargo\.toml|Cargo\.lock|bunfig\.toml|conftest\.py|sitecustomize\.py|usercustomize\.py|tsconfig(?:\.[^/]+)?\.json|\.?oxlintrc(?:\.jsonc?)?|oxlint\.config\.ts|lefthook(?:-local)?\.ya?ml|CODEOWNERS|package\.json|pyproject\.toml|pytest\.ini|pytest\.toml|setup\.cfg|tox\.ini|mypy\.ini|pyrightconfig\.json|biome\.jsonc?|\.?ruff\.toml|\.?clippy\.toml|\.?golangci\.ya?ml|Directory\.Build\.(?:props|targets)|Directory\.Packages\.props|control-plan\.json|escapes\.json|invariants\.json|chokepoints\.json|(?:vitest|vite|jest|playwright|cypress|eslint|stryker)\.config\.[cm]?[jt]s|jest\.config\.json|\.eslintrc(?:\.[^/]+)?|stryker-config\.json|mutants\.toml)$|(?:^|\/)(?:\.verification\/|\.git\/|\.husky\/|\.cargo\/|node_modules\/|bin\/vstack\.mjs$|dist\/|scripts\/|src\/hooks\/|templates\/formal\/|examples\/[^/]+\/manifest\.json$|\.claude\/|\.cursor\/|\.codex\/|\.github\/|\.grok\/|docs\/CODEOWNERS$)/i;

const importClosureCache = new Map<string, ReadonlySet<string>>();

function getSelfImportClosure(repoRoot: string): ReadonlySet<string> {
  const cached = importClosureCache.get(repoRoot);
  if (cached) return cached;
  const out = new Set<string>();
  if (!fs.existsSync(path.join(repoRoot, "bin", "vstack.mjs")) || !fs.existsSync(path.join(repoRoot, "src", "cli.ts"))) {
    importClosureCache.set(repoRoot, out);
    return out;
  }
  const queue = ["src/cli.ts", "src/hooks/index.ts"];
  while (queue.length > 0) {
    const rel = queue.pop() ?? "";
    if (!rel || out.has(rel)) continue;
    const abs = path.join(repoRoot, rel);
    if (!fs.existsSync(abs) || !fs.statSync(abs).isFile()) continue;
    out.add(rel);
    const content = fs.readFileSync(abs, "utf8");
    for (const m of content.matchAll(/(?:from|import)\s+["'](\.[^"']+)["']/g)) {
      const spec = m[1] ?? "";
      const resolved = path.posix.normalize(path.posix.join(path.posix.dirname(rel), spec));
      if (!out.has(resolved)) queue.push(resolved);
    }
  }
  importClosureCache.set(repoRoot, out);
  return out;
}

function isProtectedPath(repoRoot: string, rel: string): boolean {
  const norm = rel.replace(/\\/g, "/");
  return PROTECTED_CONTROL_PLANE.test(norm) || getSelfImportClosure(repoRoot).has(norm);
}

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

function safeRealpath(p: string): string {
  try { return fs.realpathSync(p); } catch {
    const parent = path.dirname(p);
    if (parent !== p) { try { return path.join(fs.realpathSync(parent), path.basename(p)); } catch { return path.resolve(p); } }
    return path.resolve(p);
  }
}

function resolveCanonicalRepoRoot(candidateDir: string): string {
  const abs = safeRealpath(candidateDir);
  const gitTop = runGitClean(abs, ["rev-parse", "--show-toplevel"]);
  if (gitTop.status === 0 && gitTop.stdout.trim()) {
    let top = safeRealpath(gitTop.stdout.trim());
    const parentDir = path.dirname(top);
    if (parentDir !== top) {
      const outer = runGitClean(parentDir, ["rev-parse", "--show-toplevel"]);
      if (outer.status === 0 && outer.stdout.trim()) {
        const outerTop = safeRealpath(outer.stdout.trim());
        if (fs.existsSync(path.join(outerTop, ".verification"))) top = outerTop;
      }
    }
    return top;
  }
  return abs;
}

function isHooksConfigTamperedToDisabled(repoRoot: string): boolean {
  for (const ref of ["origin/main", "origin/master", "HEAD"]) {
    const baseShow = runGitClean(repoRoot, ["show", `${ref}:.verification/hooks.json`]);
    if (baseShow.status !== 0) continue;
    try {
      const baseCfg = JSON.parse(baseShow.stdout) as Record<string, unknown>;
      if (baseCfg.enabled !== false) return true;
    } catch { continue; }
  }
  return false;
}

export function loadHookConfig(repoRoot: string): HookProjectConfig {
  const cfgPath = path.join(repoRoot, ".verification", "hooks.json");
  const defaults: HookProjectConfig = { enabled: true, tier: "immediate", harnesses: [] };
  if (!fs.existsSync(cfgPath)) return defaults;
  try {
    const parsed: unknown = JSON.parse(fs.readFileSync(cfgPath, "utf8"));
    if (!isRecord(parsed)) return defaults;
    const enabled = typeof parsed.enabled === "boolean" ? parsed.enabled : true;
    return {
      enabled: !enabled && isHooksConfigTamperedToDisabled(repoRoot) ? true : enabled,
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
  try { fs.mkdirSync(path.dirname(abs), { recursive: true }); fs.appendFileSync(abs, `${JSON.stringify({ ts: new Date().toISOString(), ...entry })}\n`, "utf8"); } catch { return; }
}

function extractPatchPaths(text: string): string[] {
  const paths: string[] = [];
  for (const m of text.matchAll(/^\s*\*\*\*\s+(?:Update|Add|Delete)\s+File:\s+(.+)$/gm)) if (m[1]) paths.push(m[1].trim());
  for (const m of text.matchAll(/^\s*\*\*\*\s+Move\s+to:\s+(.+)$/gm)) if (m[1]) paths.push(m[1].trim());
  return paths;
}

function extractPatchContentForFile(patchText: string, relOrTarget: string, base: string | undefined): string | undefined {
  const normTarget = relOrTarget.replace(/\\/g, "/").replace(/^\.\//, "");
  const lines = patchText.split(/\r?\n/);
  let active = false;
  let mode: "add" | "update" | null = null;
  const addedLines: string[] = [];
  const removedLines: string[] = [];
  for (const raw of lines) {
    const hdr = /^\s*\*\*\*\s+(Add|Update|Delete)\s+File:\s+(.+)$/.exec(raw);
    if (hdr) {
      const f = (hdr[2] ?? "").trim().replace(/\\/g, "/").replace(/^\.\//, "");
      active = f === normTarget || normTarget.endsWith(`/${f}`);
      mode = hdr[1] === "Add" ? "add" : hdr[1] === "Update" ? "update" : null;
      continue;
    }
    if (/^\s*\*\*\*\s+(?:End Patch|Move to:)/.test(raw)) { active = false; continue; }
    if (!active || !mode) continue;
    if (raw.startsWith("@@")) continue;
    if (raw.startsWith("+")) addedLines.push(raw.slice(1));
    else if (raw.startsWith("-")) removedLines.push(raw.slice(1));
  }
  if (addedLines.length === 0 && removedLines.length === 0) return undefined;
  if (mode === "add" || base === undefined) return `${addedLines.join("\n")}\n`;
  let merged = base;
  for (const rm of removedLines) {
    if (rm && merged.includes(rm)) merged = merged.replace(rm, "");
  }
  return addedLines.length > 0 ? `${merged}\n${addedLines.join("\n")}\n` : merged;
}

function extractEditedPaths(payload: Record<string, unknown>): string[] {
  const paths: string[] = [];
  const toolInput = isRecord(payload.tool_input) ? payload.tool_input : payload;
  for (const key of ["file_path", "filePath", "path", "target_file", "targetFile", "notebook_path"]) {
    const val = toolInput[key];
    if (typeof val === "string" && val.trim()) paths.push(val.trim());
  }
  for (const key of ["patch", "input", "command"]) {
    const val = toolInput[key];
    if (typeof val === "string" && val.includes("*** ")) paths.push(...extractPatchPaths(val));
  }
  if (typeof payload.input === "string" && payload.input.includes("*** ")) {
    paths.push(...extractPatchPaths(payload.input));
  }
  return [...new Set(paths)];
}

function extractProposedContent(payload: Record<string, unknown>, absFilePath: string): string | undefined {
  const toolInput = isRecord(payload.tool_input) ? payload.tool_input : payload;
  for (const key of ["content", "contents", "new_content", "file_text"]) {
    if (typeof toolInput[key] === "string") return toolInput[key];
  }
  const base = fs.existsSync(absFilePath) && fs.statSync(absFilePath).isFile() ? fs.readFileSync(absFilePath, "utf8") : undefined;
  if (Array.isArray(toolInput.edits) && base !== undefined) {
    let cur = base;
    for (const item of toolInput.edits) {
      if (!isRecord(item)) continue;
      const o = typeof item.old_string === "string" ? item.old_string : typeof item.oldString === "string" ? item.oldString : typeof item.old_str === "string" ? item.old_str : undefined;
      const n = typeof item.new_string === "string" ? item.new_string : typeof item.newString === "string" ? item.newString : typeof item.new_str === "string" ? item.new_str : undefined;
      if (o !== undefined && n !== undefined && cur.includes(o)) {
        cur = item.replace_all === true ? cur.split(o).join(n) : cur.replace(o, n);
      }
    }
    return cur;
  }
  const oldStr =
    typeof toolInput.old_string === "string" ? toolInput.old_string :
    typeof toolInput.oldString === "string" ? toolInput.oldString :
    typeof toolInput.old_str === "string" ? toolInput.old_str : undefined;
  const newStr =
    typeof toolInput.new_string === "string" ? toolInput.new_string :
    typeof toolInput.newString === "string" ? toolInput.newString :
    typeof toolInput.new_str === "string" ? toolInput.new_str : undefined;
  if (oldStr !== undefined && newStr !== undefined) {
    if (base === undefined) return newStr;
    if (base.includes(oldStr)) {
      return toolInput.replace_all === true ? base.split(oldStr).join(newStr) : base.replace(oldStr, newStr);
    }
    return `${base}\n${newStr}`;
  }
  for (const raw of [toolInput.patch, toolInput.input, toolInput.command, payload.input]) {
    if (typeof raw === "string" && raw.includes("*** ")) {
      const fromPatch = extractPatchContentForFile(raw, absFilePath, base);
      if (fromPatch !== undefined) return fromPatch;
    }
  }
  return undefined;
}

function formatReminder(header: string, findings: readonly Finding[]): string {
  const lines = [header];
  for (const f of findings.slice(0, 10)) {
    lines.push(`- [${f.severity.toUpperCase()}] ${f.rule} ${f.file}:${f.line} — ${f.message} Fix: ${f.fix}`);
  }
  if (findings.length > 10) lines.push(`... and ${findings.length - 10} more finding(s).`);
  lines.push("Fix the code directly; never disable rules, weaken configs, or add suppressions.");
  return lines.join("\n");
}

function formatPreEditDeny(harness: HookHarness, count: number, msg: string): { exitCode: number; stdout: string; stderr?: string } {
  if (harness === "codex") return { exitCode: 2, stderr: msg, stdout: "" };
  const base = { permission: "deny", user_message: `Veristack blocked write with ${count} violation(s).`, agent_message: msg };
  const out = harness === "claude" ? { ...base, hookSpecificOutput: { hookEventName: "PreToolUse", permissionDecision: "deny", permissionDecisionReason: msg } } : base;
  return { exitCode: 2, stderr: msg, stdout: JSON.stringify(out) };
}

function checkBashCommandTamper(cmd: string, repoRoot: string, baseDir: string): Finding | null {
  if (/\bgit\s+(?:remote\s+(?:remove|rm|set-url)|update-ref|config\s+(?:--local\s+)?core\.attributesFile|update-index\s+--assume-unchanged)\b/i.test(cmd)) {
    return { id: "HOOK:bash-git-tamper", rule: "hook-protected-control-plane", category: "cheat", rung: "R0", severity: "error", file: ".git", line: 1, message: "Direct agent git control-plane tampering command is blocked.", fix: "Do not tamper with git remotes, refs, attributes, or index flags." };
  }
  const targets: string[] = [];
  for (const m of cmd.matchAll(/(?:>>?|tee(?:\s+-a)?|rm(?:\s+-[rf]+)?|mv|cp|sed\s+-i(?:\s+['"][^'"]*['"])?)\s+["']?([^\s"'|;&]+)["']?/g)) {
    if (m[1]) targets.push(m[1]);
  }
  for (const t of targets) {
    const abs = safeRealpath(path.isAbsolute(t) ? t : path.resolve(baseDir, t));
    const rel = path.relative(repoRoot, abs).split(path.sep).join("/");
    if (isProtectedPath(repoRoot, rel)) {
      return { id: `HOOK:bash-protected:${rel}`, rule: "hook-protected-control-plane", category: "cheat", rung: "R0", severity: "error", file: rel, line: 1, message: `Shell command mutates protected control-plane file '${rel}'.`, fix: "Do not modify verification configs, manifests, hooks, or gate code via shell." };
    }
  }
  return null;
}

function listGitDirtyFiles(repoRoot: string): string[] {
  const res = runGitClean(repoRoot, ["status", "-z", "--untracked-files=all"]);
  if (res.status !== 0) return [];
  const tokens = (res.stdout ?? "").split("\0");
  const out: string[] = [];
  for (let i = 0; i < tokens.length; i++) {
    const entry = tokens[i] ?? "";
    if (entry.length < 4) continue;
    const status = entry.slice(0, 2);
    const rel = entry.slice(3);
    if (status.includes("R") || status.includes("C")) {
      const next = tokens[i + 1];
      if (next) out.push(rel);
      i += 1;
    } else if (rel) {
      out.push(rel);
    }
  }
  return out;
}

export function executeHookEvent(
  event: HookEventKind,
  rawStdin: string,
  options: { repoRoot?: string; harness?: HookHarness; tier?: CheckFileTier } = {},
): HookExecutionResult {
  const harness: HookHarness = options.harness ?? "claude";
  const hookDisabledEnv = process.env.VSTACK_HOOK_DISABLED === "1";
  if (hookDisabledEnv && event !== "pre-edit") return { exitCode: 0, stdout: "", findings: [] };

  let payload: Record<string, unknown> = {};
  if (!rawStdin.trim()) {
    if (event === "pre-edit") {
      const deny = formatPreEditDeny(harness, 1, "Veristack blocked pre-edit: empty stdin payload (fail-closed).");
      return { ...deny, findings: [] };
    }
  } else {
    try {
      const parsed: unknown = JSON.parse(rawStdin);
      if (isRecord(parsed)) payload = parsed;
      else if (event === "pre-edit") {
        const deny = formatPreEditDeny(harness, 1, "Veristack blocked pre-edit: non-object JSON payload.");
        return { ...deny, findings: [] };
      } else if (event === "stop") {
        return { exitCode: 0, stdout: JSON.stringify({ decision: "block", reason: "Veristack blocked stop: non-object JSON payload (fail-closed)." }), findings: [] };
      }
    } catch {
      if (event === "pre-edit") {
        const deny = formatPreEditDeny(harness, 1, "Veristack blocked pre-edit: malformed JSON payload (fail-closed).");
        return { ...deny, findings: [] };
      }
      if (event === "stop") {
        return { exitCode: 0, stdout: JSON.stringify({ decision: "block", reason: "Veristack blocked stop: malformed JSON payload (fail-closed)." }), findings: [] };
      }
      return { exitCode: 0, stdout: "", findings: [] };
    }
  }

  const baseDir = options.repoRoot ?? (typeof payload.cwd === "string" && payload.cwd.trim() ? payload.cwd.trim() : process.cwd());
  const repoRoot = resolveCanonicalRepoRoot(baseDir);
  const config = loadHookConfig(repoRoot);
  if (!config.enabled && event !== "pre-edit") return { exitCode: 0, stdout: "", findings: [] };

  const tier: CheckFileTier = options.tier ?? (harness === "copilot" ? "all" : config.tier);
  const sessionId = typeof payload.session_id === "string" && payload.session_id.trim() ? payload.session_id.trim() : "default";
  const statePath = sessionStatePath(repoRoot, sessionId);

  if (event === "pre-edit") {
    const toolName = typeof payload.tool_name === "string" ? payload.tool_name : "";
    const toolInput = isRecord(payload.tool_input) ? payload.tool_input : payload;
    if (toolName === "Bash" && typeof toolInput.command === "string") {
      const bashHit = checkBashCommandTamper(toolInput.command, repoRoot, baseDir);
      if (bashHit) {
        const msg = formatReminder("Veristack blocked shell control-plane tampering:", [bashHit]);
        return { ...formatPreEditDeny(harness, 1, msg), findings: [bashHit] };
      }
      return { exitCode: 0, stdout: harness === "codex" ? "" : JSON.stringify({ permission: "allow" }), findings: [] };
    }
    const edited = extractEditedPaths(payload);
    if (edited.length === 0) {
      const deny = formatPreEditDeny(harness, 1, "Veristack blocked pre-edit: no extractable target file path in payload (fail-closed).");
      return { ...deny, findings: [] };
    }
    const findings: Finding[] = [];
    for (const filePath of edited) {
      const abs = safeRealpath(path.isAbsolute(filePath) ? filePath : path.resolve(baseDir, filePath));
      if (fs.existsSync(abs) && fs.statSync(abs).isDirectory()) continue;
      const rel = path.relative(repoRoot, abs).split(path.sep).join("/");
      if (isProtectedPath(repoRoot, rel)) {
        findings.push({
          id: `HOOK:protected:${rel}`,
          rule: "hook-protected-control-plane",
          category: "cheat",
          rung: "R0",
          severity: "error",
          file: rel,
          line: 1,
          message: `Direct agent edit to verification control-plane/config file '${rel}' is blocked by pre-edit policy.`,
          fix: "Fix the underlying code defect instead of weakening verification configs, manifests, receipts, or hooks.",
        });
        continue;
      }
      if (hookDisabledEnv || !config.enabled) continue;
      const proposed = extractProposedContent(payload, abs);
      if (proposed === undefined) {
        if (toolName === "Delete") continue;
        const hasWriteIntent = /^(?:Write|Edit|MultiEdit|StrReplace|NotebookEdit|apply_patch)$/i.test(toolName) || Object.keys(toolInput).some((k) => !/^(?:file_path|filePath|path|target_file|targetFile|notebook_path|cwd)$/.test(k));
        if (hasWriteIntent) {
          findings.push({ id: `HOOK:unextractable:${rel}`, rule: "hook-unextractable-write", category: "cheat", rung: "R0", severity: "error", file: rel, line: 1, message: `Unable to extract proposed edit content for '${rel}' (fail-closed).`, fix: "Use standard Edit/Write/MultiEdit/apply_patch payload keys so pre-edit verification can inspect the change." });
          continue;
        }
        if (!fs.existsSync(abs)) continue;
      }
      if (proposed !== undefined && hasPathologicalNesting(proposed)) {
        findings.push({ id: `HOOK:syntax-bomb:${rel}`, rule: "syntax-nesting-bomb", category: "cheat", rung: "R0", severity: "error", file: rel, line: 1, message: `Proposed edit to '${rel}' contains pathological syntax nesting or size (>128 depth or >2 MiB) — blocked fail-closed.`, fix: "Remove deeply nested expressions or oversized generated payloads." });
        continue;
      }
      const res = scanSingleFile(abs, { repoRoot, tier: "immediate", content: proposed, strict: true });
      findings.push(...res.findings);
    }
    appendAuditLog(repoRoot, config.auditLog, { event, harness, files: edited, findings: findings.length });
    if (findings.length === 0) return { exitCode: 0, stdout: harness === "codex" ? "" : JSON.stringify({ permission: "allow" }), findings: [] };
    const msg = formatReminder(`Veristack blocked write (${findings.length} immediate slop/cheat violation(s)):`, findings);
    const deny = formatPreEditDeny(harness, findings.length, msg);
    return { ...deny, findings };
  }

  if (event === "post-edit") {
    const edited = extractEditedPaths(payload);
    if (edited.length === 0) return { exitCode: 0, stdout: "", findings: [] };
    const state = readSessionState(statePath);
    const touchedSet = new Set(state.touchedFiles);
    const findings: Finding[] = [];
    for (const filePath of edited) {
      const abs = safeRealpath(path.isAbsolute(filePath) ? filePath : path.resolve(baseDir, filePath));
      if (!fs.existsSync(abs) || !fs.statSync(abs).isFile()) continue;
      const res = scanSingleFile(abs, { repoRoot, tier, strict: true });
      touchedSet.add(res.file);
      findings.push(...res.findings);
    }
    writeSessionState(statePath, { touchedFiles: [...touchedSet], reportedKeys: state.reportedKeys });
    appendAuditLog(repoRoot, config.auditLog, { event, harness, files: edited, findings: findings.length });
    if (findings.length === 0 || harness === "grok") return { exitCode: 0, stdout: "", findings };
    const msg = formatReminder(`Veristack detected ${findings.length} issue(s) on your edit — fix before continuing:`, findings);
    return {
      exitCode: 0,
      stdout: JSON.stringify({ hookSpecificOutput: { hookEventName: "PostToolUse", additionalContext: msg } }),
      findings,
    };
  }

  if (payload.reason === "shutdown") return { exitCode: 0, stdout: "", findings: [] };

  const state = readSessionState(statePath);
  const candidateFiles = new Set<string>([...state.touchedFiles, ...listGitDirtyFiles(repoRoot)]);
  const findings: Finding[] = [];
  for (const rel of candidateFiles) {
    const abs = path.resolve(repoRoot, rel);
    if (!fs.existsSync(abs) || !fs.statSync(abs).isFile()) continue;
    const res = scanSingleFile(abs, { repoRoot, tier: "all", strict: true });
    findings.push(...res.findings);
  }
  const stopBaseRef = (() => {
    for (const cand of ["origin/main", "origin/master"]) {
      if (runGitClean(repoRoot, ["rev-parse", "--verify", `${cand}^{commit}`]).status === 0) return cand;
    }
    return "HEAD";
  })();
  for (const cheat of scanGitDiffCheats(repoRoot, stopBaseRef)) findings.push(cheat);
  for (const mf of [".verification/hooks.json", ".claude/settings.local.json", ".codex/hooks.json", ".cursor/hooks.json"]) {
    if (!fs.existsSync(path.join(repoRoot, mf)) && runGitClean(repoRoot, ["cat-file", "-e", `${stopBaseRef}:${mf}`]).status === 0) {
      findings.push({ id: `HOOK:deleted:${mf}`, rule: "hook-protected-control-plane", category: "cheat", rung: "R0", severity: "error", file: mf, line: 1, message: `Protected hook manifest '${mf}' was deleted compared to ${stopBaseRef}.`, fix: `Restore '${mf}' or run 'vstack hooks on'.` });
    }
  }
  if (isHooksConfigTamperedToDisabled(repoRoot)) {
    const cfgPath = path.join(repoRoot, ".verification", "hooks.json");
    try {
      const rawCfg = JSON.parse(fs.readFileSync(cfgPath, "utf8")) as Record<string, unknown>;
      if (rawCfg.enabled === false) {
        findings.push({ id: "HOOK:tampered:.verification/hooks.json", rule: "hook-protected-control-plane", category: "cheat", rung: "R0", severity: "error", file: ".verification/hooks.json", line: 1, message: "Agent disabled Veristack hooks by setting enabled: false in .verification/hooks.json.", fix: "Restore enabled: true in .verification/hooks.json." });
      }
    } catch { void 0; }
  }
  if (findings.length === 0) {
    try { if (fs.existsSync(statePath)) fs.unlinkSync(statePath); } catch { void 0; }
  }
  appendAuditLog(repoRoot, config.auditLog, { event, harness, touched: candidateFiles.size, findings: findings.length });
  if (findings.length === 0) return { exitCode: 0, stdout: "", findings: [] };

  const msg = formatReminder(`Veristack deep stop-pass found ${findings.length} unaddressed issue(s):`, findings);
  if (harness === "grok") return { exitCode: 0, stdout: JSON.stringify({ additionalContext: msg }), findings };
  return { exitCode: 0, stdout: JSON.stringify({ decision: "block", reason: msg }), findings };
}
