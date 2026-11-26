import { spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { auditAgentDocs } from "../anti-slop/agent-docs.ts";
import { discoverRepo } from "../discover.ts";
import { globMatchesPath } from "../rungs/workflow-audit.ts";
import { auditFormalSync } from "../zero-defect/formal-sync.ts";
import { auditZeroDefectArtifacts } from "../zero-defect/index.ts";
import { loadRepoConfig } from "../zero-defect/repo-config.ts";
import { manageHooks } from "./install.ts";

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

export function runDoctor(repoPath: string): DoctorReport {
  const absTarget = path.resolve(repoPath);
  if (!fs.existsSync(absTarget) || !fs.statSync(absTarget).isDirectory()) {
    throw new Error(`Directory not found: ${repoPath}`);
  }
  const repo = discoverRepo(repoPath);
  const findings: DoctorFinding[] = [];
  const hookStatus = manageHooks(repo.root, "status");

  if (process.env.VSTACK_HOOK_DISABLED === "1") {
    findings.push({
      id: "DOC:hooks-env-disabled",
      level: "mention",
      artifact: "env",
      summary: "VSTACK_HOOK_DISABLED=1 disables Veristack agent hooks globally.",
      fix: "Unset VSTACK_HOOK_DISABLED so agent hooks run.",
    });
  }
  const hookCfgAbs = path.join(repo.root, ".verification", "hooks.json");
  if (fs.existsSync(hookCfgAbs)) {
    try {
      const hc = JSON.parse(fs.readFileSync(hookCfgAbs, "utf8")) as Record<string, unknown>;
      if (hc.enabled === false) {
        findings.push({
          id: "DOC:hooks-paused:.verification/hooks.json",
          level: "mention",
          artifact: ".verification/hooks.json",
          summary: ".verification/hooks.json sets enabled: false, pausing Veristack agent hooks.",
          fix: "Run 'vstack hooks on' or set enabled: true.",
        });
      }
      const declaredHarnesses = Array.isArray(hc.harnesses) ? hc.harnesses.filter((h): h is string => typeof h === "string") : [];
      if (hc.enabled !== false && declaredHarnesses.length > 0) {
        const missingActive = declaredHarnesses.filter((h) => !hookStatus.harnesses.includes(h as never));
        if (missingActive.length > 0) {
          findings.push({
            id: "DOC:hooks-incomplete:.verification/hooks.json",
            level: "mention",
            artifact: ".verification/hooks.json",
            summary: `Declared hook harness(es) [${missingActive.join(", ")}] are missing, tampered, or lack active PreToolUse/PostToolUse/Stop wiring.`,
            fix: "Run 'vstack hooks on' to reinstall valid fail-closed hook manifests.",
          });
        }
      }
    } catch {
      findings.push({
        id: "DOC:malformed-hook:.verification/hooks.json",
        level: "auto",
        artifact: ".verification/hooks.json",
        summary: "Hook config .verification/hooks.json contains invalid JSON.",
        fix: "Repair or rerun 'vstack hooks on'.",
      });
    }
  }
  const allowPatterns = repo.manifest?.allowExcluded ?? [];
  const unallowlistedExclusions = repo.scopeExclusions.filter((ex) => {
    const norm = ex.path.replace(/\\/g, "/");
    return !allowPatterns.some((pat) => globMatchesPath(pat, norm) || globMatchesPath(pat, `${norm}/`));
  });
  if (unallowlistedExclusions.length > 0) {
    findings.push({
      id: "DOC:scope-exclusions:.vstackignore",
      level: "mention",
      artifact: ".vstackignore",
      summary: `${unallowlistedExclusions.length} unallowlisted path(s) excluded from scan scope via .vstackignore or ignore rules.`,
      fix: "Remove broad .vstackignore exclusions so all production and test files stay verified.",
    });
  }

  const probedCmds = new Map<string, boolean>();
  for (const rel of HOOK_MANIFESTS) {
    const abs = path.join(repo.root, rel);
    if (!fs.existsSync(abs)) continue;
    try {
      const parsed = JSON.parse(fs.readFileSync(abs, "utf8")) as Record<string, unknown>;
      if (parsed && typeof parsed === "object" && parsed.disableAllHooks === true) {
        findings.push({
          id: `DOC:hooks-disabled:${rel}`,
          level: "mention",
          artifact: rel,
          summary: `${rel} sets disableAllHooks: true, silently disabling Veristack agent hooks.`,
          fix: "Remove disableAllHooks: true so per-edit and stop hooks execute.",
        });
      }
      if (parsed && typeof parsed === "object" && typeof parsed.hooks === "object" && parsed.hooks !== null) {
        const hooksObj = parsed.hooks as Record<string, unknown>;
        const cmds: string[] = [];
        const collectCmds = (bucket: unknown): void => {
          if (!Array.isArray(bucket)) return;
          for (const item of bucket) {
            if (!item || typeof item !== "object") continue;
            const rec = item as Record<string, unknown>;
            if (typeof rec.command === "string") cmds.push(rec.command);
            if (Array.isArray(rec.hooks)) {
              for (const sub of rec.hooks) {
                if (sub && typeof sub === "object" && typeof (sub as Record<string, unknown>).command === "string") {
                  cmds.push((sub as Record<string, unknown>).command as string);
                }
              }
            }
          }
        };
        for (const b of Object.values(hooksObj)) collectCmds(b);
        let badCmd: string | undefined;
        let preCmd: string | undefined;
        for (const c of cmds) {
          if (!badCmd && /\bvstack\b/i.test(c) && /\|\|\s*(?:true|:)|;\s*true\b|>\/dev\/null/i.test(c)) badCmd = c;
          if (!preCmd && /\bhook\s+pre-edit\b/.test(c) && !/[;|>&`\n\r]/.test(c)) preCmd = c;
        }
        if (badCmd) {
          findings.push({
            id: `DOC:hook-swallowed:${rel}`,
            level: "mention",
            artifact: rel,
            summary: `${rel} wraps a Veristack hook command in a failure-swallowing shell suffix ('${badCmd.slice(0, 80)}').`,
            fix: "Remove '|| true' / redirection wrappers so hook denials propagate cleanly.",
          });
        }
        if (hookStatus.enabled && preCmd && !badCmd) {
          let probePassed = probedCmds.get(preCmd);
          if (probePassed === undefined) {
            const argv = preCmd.trim().split(/\s+/);
            const bin = argv[0] ?? "";
            const probePayload = JSON.stringify({
              cwd: repo.root,
              tool_input: { file_path: path.join(repo.root, ".verification", "rungs.json"), content: "{}" },
            });
            const probe = spawnSync(bin, argv.slice(1), { cwd: repo.root, input: probePayload, encoding: "utf8", timeout: 5_000, shell: false });
            const denied = probe.status === 2 || /"permission"\s*:\s*"deny"|"permissionDecision"\s*:\s*"deny"/.test(`${probe.stdout}\n${probe.stderr}`);
            probePassed = !probe.error && denied;
            probedCmds.set(preCmd, probePassed);
          }
          if (!probePassed) {
            findings.push({
              id: `DOC:hook-probe-failed:${rel}`,
              level: "mention",
              artifact: rel,
              summary: `Live pre-edit probe of '${preCmd}' in ${rel} failed to deny a synthetic control-plane write.`,
              fix: "Point hook command to a working current Veristack binary (e.g. 'node bin/vstack.mjs' or updated local install).",
            });
          }
        }
      }
    } catch {
      findings.push({
        id: `DOC:malformed-hook:${rel}`,
        level: "auto",
        artifact: rel,
        summary: `Hook manifest ${rel} contains invalid JSON.`,
        fix: "Repair or rerun 'vstack hooks on' to regenerate valid hook manifests.",
      });
    }
  }

  const cfg = loadRepoConfig(repo.root);
  if (cfg.configPath) {
    const weakened = Object.entries(cfg.rules)
      .filter(([, sev]) => sev === "off" || sev === "info" || sev === "warn")
      .map(([rule, sev]) => `${rule}=${sev}`);
    if (weakened.length > 0) {
      findings.push({
        id: `DOC:disabled-rules:${cfg.configPath}`,
        level: "mention",
        artifact: cfg.configPath,
        summary: `${cfg.configPath} disables or downgrades ${weakened.length} Veristack rule(s): ${weakened.join(", ")}.`,
        fix: "Re-enable disabled/downgraded rules to run Veristack at full rigidity (--strict).",
      });
    }
    if (cfg.ignore.length > 0) {
      findings.push({
        id: `DOC:config-ignore:${cfg.configPath}`,
        level: "mention",
        artifact: cfg.configPath,
        summary: `${cfg.configPath} ignores ${cfg.ignore.length} path pattern(s): ${cfg.ignore.join(", ")}.`,
        fix: "Remove config ignore exclusions so all source/test paths remain verified.",
      });
    }
  }

  for (const f of auditFormalSync(repo)) {
    findings.push({
      id: `DOC:${f.rule}:${f.file}`,
      level: "route",
      artifact: f.file,
      summary: f.message,
      fix: f.fix,
    });
  }

  for (const f of auditZeroDefectArtifacts(repo)) {
    if (f.rule.startsWith("formal-sync-")) continue;
    findings.push({
      id: `DOC:${f.rule}:${f.file}`,
      level: "mention",
      artifact: f.file,
      summary: f.message,
      fix: f.fix,
    });
  }

  for (const f of auditAgentDocs(repo)) {
    if (f.severity === "info") continue;
    findings.push({
      id: `DOC:${f.rule}:${f.file}:${f.line}`,
      level: "mention",
      artifact: f.file,
      summary: f.message,
      fix: f.fix,
    });
  }

  return {
    schemaVersion: 1,
    repo: repo.root,
    healthy: findings.length === 0,
    hooksEnabled: hookStatus.enabled,
    installedHarnesses: hookStatus.harnesses,
    findings,
  };
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
