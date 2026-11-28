import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { auditAgentDocs } from "@veristack/plugin-agent-docs";
import { getCoreServices, loadRepoConfig, pathHelpers, runGitClean, type DiscoveredRepo } from "@veristack/plugin";
import { auditFormalSync } from "@veristack/plugin-laws-formal";
import { auditZeroDefectArtifacts } from "@veristack/plugin-zero-defect";
import { manageHooks } from "./install.ts";
import { evaluateGreenfieldRungGate } from "@veristack/plugin-control-plane";

export type DoctorActionLevel = "auto" | "mention" | "route";

export interface DoctorFinding {
  id: string;
  level: DoctorActionLevel;
  artifact: string;
  summary: string;
  fix: string;
}

export interface DoctorReport {
  schemaVersion: 1;
  repo: string;
  healthy: boolean;
  hooksEnabled: boolean;
  installedHarnesses: string[];
  findings: DoctorFinding[];
}

const HOOK_MANIFESTS = [
  ".claude/settings.json",
  ".claude/settings.local.json",
  ".codex/hooks.json",
  ".cursor/hooks.json",
  ".github/hooks/veristack.json",
  ".grok/hooks/veristack.json",
  ".verification/hooks.json",
];

function auditHooksConfigFile(
  repoRoot: string,
  hookStatus: ReturnType<typeof manageHooks>,
  findings: DoctorFinding[],
): void {
  if (!repoRoot) return;
  if (process.env.VSTACK_HOOK_DISABLED === "1") {
    findings.push({
      id: "DOC:hooks-env-disabled", level: "mention", artifact: "env",
      summary: "VSTACK_HOOK_DISABLED=1 disables Veristack agent hooks globally.",
      fix: "Unset VSTACK_HOOK_DISABLED so agent hooks run.",
    });
  }
  const hookCfgAbs = path.join(repoRoot, ".verification", "hooks.json");
  if (!fs.existsSync(hookCfgAbs)) {
    if (runGitClean(repoRoot, ["cat-file", "-e", "HEAD:.verification/hooks.json"]).status === 0) {
      findings.push({
        id: "DOC:hooks-deleted:.verification/hooks.json", level: "mention", artifact: ".verification/hooks.json",
        summary: ".verification/hooks.json existed at HEAD and was deleted in the working tree.",
        fix: "Restore .verification/hooks.json or run 'vstack hooks on'.",
      });
    }
    return;
  }
  try {
    const hc = JSON.parse(fs.readFileSync(hookCfgAbs, "utf8")) as Record<string, unknown>;
    if (hc.enabled === false) {
      findings.push({
        id: "DOC:hooks-paused:.verification/hooks.json", level: "mention", artifact: ".verification/hooks.json",
        summary: ".verification/hooks.json sets enabled: false, pausing Veristack agent hooks.",
        fix: "Run 'vstack hooks on' or set enabled: true.",
      });
    }
    const declared = Array.isArray(hc.harnesses) ? hc.harnesses.filter((h): h is string => typeof h === "string") : [];
    const missing = hc.enabled !== false ? declared.filter((h) => !hookStatus.harnesses.includes(h as never)) : [];
    if (missing.length > 0) {
      findings.push({
        id: "DOC:hooks-incomplete:.verification/hooks.json", level: "mention", artifact: ".verification/hooks.json",
        summary: `Declared hook harness(es) [${missing.join(", ")}] are missing, tampered, or lack active PreToolUse/PostToolUse/Stop wiring.`,
        fix: "Run 'vstack hooks on' to reinstall valid fail-closed hook manifests.",
      });
    }
  } catch {
    findings.push({
      id: "DOC:malformed-hook:.verification/hooks.json", level: "auto", artifact: ".verification/hooks.json",
      summary: "Hook config .verification/hooks.json contains invalid JSON.",
      fix: "Repair or rerun 'vstack hooks on'.",
    });
  }
}

function collectManifestCommands(hooksObj: Record<string, unknown>): string[] {
  const cmds: string[] = [];
  for (const bucket of Object.values(hooksObj)) {
    if (!Array.isArray(bucket)) continue;
    for (const item of bucket) {
      if (!item || typeof item !== "object") continue;
      const rec = item as Record<string, unknown>;
      if (typeof rec.command === "string") cmds.push(rec.command);
      if (!Array.isArray(rec.hooks)) continue;
      for (const sub of rec.hooks) {
        if (sub && typeof sub === "object" && typeof (sub as Record<string, unknown>).command === "string") {
          cmds.push((sub as Record<string, unknown>).command as string);
        }
      }
    }
  }
  return cmds;
}

function probePreEditCommand(repoRoot: string, preCmd: string, probedCmds: Map<string, boolean>): boolean {
  const cached = probedCmds.get(preCmd);
  if (cached !== undefined) return cached;
  const probeCwd = fs.existsSync(path.join(repoRoot, "src")) ? path.join(repoRoot, "src") : repoRoot;
  const shMatch = /^sh\s+-c\s+'(.+)'$/.exec(preCmd.trim());
  const bin = shMatch ? "sh" : (preCmd.trim().split(/\s+/)[0] ?? "");
  const args = shMatch ? ["-c", shMatch[1] ?? ""] : preCmd.trim().split(/\s+/).slice(1);
  const runProbe = (payloadObj: object): boolean => {
    const p = spawnSync(bin, args, { cwd: probeCwd, input: JSON.stringify(payloadObj), encoding: "utf8", timeout: 5_000, shell: false });
    return !p.error && p.status === 2;
  };
  const cpOk = runProbe({ cwd: probeCwd, tool_name: "Write", tool_input: { file_path: path.join(repoRoot, ".verification", "rungs.json"), content: "{}" } });
  const slopOk = runProbe({ cwd: probeCwd, tool_name: "Write", tool_input: { file_path: path.join(repoRoot, "src", "__probe__.ts"), content: "export const x = (1 as any);\n" } });
  const passed = cpOk && slopOk;
  probedCmds.set(preCmd, passed);
  return passed;
}

function auditHookManifestFile(ctx: {
  repoRoot: string;
  rel: string;
  hooksEnabled: boolean;
  probedCmds: Map<string, boolean>;
  findings: DoctorFinding[];
}): void {
  const { repoRoot, rel, hooksEnabled, probedCmds, findings } = ctx;
  const abs = path.join(repoRoot, rel);
  if (!fs.existsSync(abs)) return;
  let parsed: Record<string, unknown>;
  try {
    parsed = JSON.parse(fs.readFileSync(abs, "utf8")) as Record<string, unknown>;
  } catch {
    findings.push({ id: `DOC:malformed-hook:${rel}`, level: "auto", artifact: rel, summary: `Hook manifest ${rel} contains invalid JSON.`, fix: "Repair or rerun 'vstack hooks on' to regenerate valid hook manifests." });
    return;
  }
  if (!parsed || typeof parsed !== "object") return;
  if (parsed.disableAllHooks === true) {
    findings.push({ id: `DOC:hooks-disabled:${rel}`, level: "mention", artifact: rel, summary: `${rel} sets disableAllHooks: true, silently disabling Veristack agent hooks.`, fix: "Remove disableAllHooks: true so per-edit and stop hooks execute." });
  }
  if (typeof parsed.env === "object" && parsed.env !== null && (parsed.env as Record<string, unknown>).VSTACK_HOOK_DISABLED === "1") {
    findings.push({ id: `DOC:hooks-env-disabled:${rel}`, level: "mention", artifact: rel, summary: `${rel} sets env.VSTACK_HOOK_DISABLED=1, disabling Veristack hooks.`, fix: "Remove VSTACK_HOOK_DISABLED from settings env." });
  }
  if (typeof parsed.hooks !== "object" || parsed.hooks === null) return;
  const cmds = collectManifestCommands(parsed.hooks as Record<string, unknown>);
  const badCmd = cmds.find((c) => /\bvstack\b/i.test(c) && /\|\|\s*(?:true|:)|;\s*true\b|(?:^|[^2])>\/dev\/null/i.test(c));
  const preCmd = cmds.find((c) => /\bhook\s+pre-edit\b/.test(c));
  if (badCmd) {
    findings.push({ id: `DOC:hook-swallowed:${rel}`, level: "mention", artifact: rel, summary: `${rel} wraps a Veristack hook command in a failure-swallowing shell suffix ('${badCmd.slice(0, 80)}').`, fix: "Remove '|| true' / redirection wrappers so hook denials propagate cleanly." });
  }
  if (hooksEnabled && preCmd && !badCmd && !probePreEditCommand(repoRoot, preCmd, probedCmds)) {
    findings.push({ id: `DOC:hook-probe-failed:${rel}`, level: "mention", artifact: rel, summary: `Live subdirectory pre-edit probe of '${preCmd}' in ${rel} failed to exit 2 on synthetic control-plane and slop writes.`, fix: "Reinstall root-anchored fail-closed hooks via 'vstack hooks on'." });
  }
}

function auditDoctorConfigAndArtifacts(repo: DiscoveredRepo, findings: DoctorFinding[]): void {
  if (!repo.root) throw new Error("Repo root is required.");
  const cfg = loadRepoConfig(repo.root);
  if (cfg.configPath) {
    const weakened = Object.entries(cfg.rules).filter(([, sev]) => sev === "off" || sev === "info" || sev === "warn").map(([rule, sev]) => `${rule}=${sev}`);
    if (weakened.length > 0) {
      findings.push({ id: `DOC:disabled-rules:${cfg.configPath}`, level: "mention", artifact: cfg.configPath, summary: `${cfg.configPath} disables or downgrades ${weakened.length} Veristack rule(s): ${weakened.join(", ")}.`, fix: "Re-enable disabled/downgraded rules to run Veristack at full rigidity (--strict)." });
    }
    if (cfg.ignore.length > 0) {
      findings.push({ id: `DOC:config-ignore:${cfg.configPath}`, level: "mention", artifact: cfg.configPath, summary: `${cfg.configPath} ignores ${cfg.ignore.length} path pattern(s): ${cfg.ignore.join(", ")}.`, fix: "Remove config ignore exclusions so all source/test paths remain verified." });
    }
  }
  for (const f of auditFormalSync(repo)) {
    findings.push({ id: `DOC:${f.rule}:${f.file}`, level: "route", artifact: f.file, summary: f.message, fix: f.fix });
  }
  for (const f of auditZeroDefectArtifacts(repo)) {
    if (!f.rule.startsWith("formal-sync-")) findings.push({ id: `DOC:${f.rule}:${f.file}`, level: "mention", artifact: f.file, summary: f.message, fix: f.fix });
  }
  for (const f of auditAgentDocs(repo)) {
    if (f.severity !== "info") findings.push({ id: `DOC:${f.rule}:${f.file}:${f.line}`, level: "mention", artifact: f.file, summary: f.message, fix: f.fix });
  }
  for (const f of evaluateGreenfieldRungGate(repo)) {
    findings.push({ id: `DOC:${f.id}`, level: "route", artifact: f.file, summary: f.message, fix: f.fix });
  }
  auditEffectiveFpLedger(repo.root, findings);
}

function auditEffectiveFpLedger(repoRoot: string, findings: DoctorFinding[]): void {
  const escAbs = path.join(repoRoot, ".verification", "escapes.json");
  if (!fs.existsSync(escAbs)) return;
  let parsed: unknown;
  try { parsed = JSON.parse(fs.readFileSync(escAbs, "utf8")); } catch { return; }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return;
  const stats = (parsed as Record<string, unknown>).ruleFeedback;
  if (!Array.isArray(stats)) return;
  for (const entry of stats) {
    if (!entry || typeof entry !== "object") continue;
    const rec = entry as Record<string, unknown>;
    const rule = typeof rec.rule === "string" ? rec.rule : "";
    const dismissed = typeof rec.dismissed === "number" ? rec.dismissed : 0;
    const fixed = typeof rec.fixed === "number" ? rec.fixed : 0;
    const total = dismissed + fixed;
    if (!rule || total < 5) continue;
    const fpRate = dismissed / total;
    if (fpRate > 0.1) {
      findings.push({
        id: `DOC:high-fp-rule:${rule}`, level: "mention", artifact: ".verification/escapes.json",
        summary: `Rule '${rule}' effective FP/dismissal rate is ${(fpRate * 100).toFixed(1)}% (${dismissed}/${total}, Tricorder ceiling: 10%).`,
        fix: `Tighten '${rule}' precision or reclassify it as hygiene-lint until effective FP rate drops <= 10%.`,
      });
    }
  }
}

export function runDoctor(repoPath: string): DoctorReport {
  const absTarget = path.resolve(repoPath);
  if (!fs.existsSync(absTarget) || !fs.statSync(absTarget).isDirectory()) {
    throw new Error(`Directory not found: ${repoPath}`);
  }
  const repo = (getCoreServices().discoverRepo ?? (() => { throw new Error("Core discoverRepo service not registered."); }))(repoPath);
  const findings: DoctorFinding[] = [];
  const hookStatus = manageHooks(repo.root, "status");
  auditHooksConfigFile(repo.root, hookStatus, findings);

  const allowPatterns = repo.manifest?.allowExcluded ?? [];
  const unallowlistedExclusions = repo.scopeExclusions.filter((ex) => {
    const norm = ex.path.replace(/\\/g, "/");
    return !allowPatterns.some((pat) => pathHelpers.globMatchesPath(pat, norm) || pathHelpers.globMatchesPath(pat, `${norm}/`));
  });
  if (unallowlistedExclusions.length > 0) {
    findings.push({
      id: "DOC:scope-exclusions:.vstackignore", level: "mention", artifact: ".vstackignore",
      summary: `${unallowlistedExclusions.length} unallowlisted path(s) excluded from scan scope via .vstackignore or ignore rules.`,
      fix: "Remove broad .vstackignore exclusions so all production and test files stay verified.",
    });
  }

  const probedCmds = new Map<string, boolean>();
  for (const rel of HOOK_MANIFESTS) {
    auditHookManifestFile({ repoRoot: repo.root, rel, hooksEnabled: hookStatus.enabled, probedCmds, findings });
  }
  auditDoctorConfigAndArtifacts(repo, findings);

  const codexCfg = path.join(os.homedir(), ".codex", "config.toml");
  let codexUntrusted = false;
  if (hookStatus.harnesses.includes("codex") && fs.existsSync(codexCfg)) {
    try {
      const cRaw = fs.readFileSync(codexCfg, "utf8");
      const realRoot = (() => { try { return fs.realpathSync(repo.root); } catch { return repo.root; } })();
      codexUntrusted = !cRaw.includes(repo.root) && !cRaw.includes(realRoot);
    } catch { codexUntrusted = false; }
  }
  const installedHarnesses = hookStatus.harnesses.map((h) => (h === "codex" && codexUntrusted ? "codex (installed; untrusted)" : h));
  return { schemaVersion: 1, repo: repo.root, healthy: findings.length === 0, hooksEnabled: hookStatus.enabled, installedHarnesses, findings };
}

export function formatDoctorReport(report: DoctorReport): string {
  const hookLine = report.hooksEnabled
    ? `ON (${report.installedHarnesses.join(", ")})`
    : "OFF (run 'vstack hooks on' to enable per-edit agent hooks)";
  const lines = [
    `vstack doctor: ${report.healthy ? "HEALTHY" : `${report.findings.length} drift finding(s)`} | hooks: ${hookLine}`,
  ];
  for (const f of report.findings) {
    lines.push(`  - [${f.level.toUpperCase()}] ${f.artifact} — ${f.summary}`);
    lines.push(`      Fix: ${f.fix}`);
  }
  return lines.join("\n");
}
