import fs from "node:fs";
import path from "node:path";
import { auditAgentDocs } from "../anti-slop/agent-docs.ts";
import { discoverRepo } from "../discover.ts";
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
  ".claude/settings.local.json",
  ".codex/hooks.json",
  ".cursor/hooks.json",
  ".github/hooks/veristack.json",
  ".grok/hooks/veristack.json",
  ".verification/hooks.json",
];

export function runDoctor(repoPath: string): DoctorReport {
  const repo = discoverRepo(repoPath);
  const findings: DoctorFinding[] = [];
  const hookStatus = manageHooks(repo.root, "status");

  for (const rel of HOOK_MANIFESTS) {
    const abs = path.join(repo.root, rel);
    if (!fs.existsSync(abs)) continue;
    try {
      JSON.parse(fs.readFileSync(abs, "utf8"));
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
  if (cfg.configPath && Object.values(cfg.rules).includes("off")) {
    const disabled = Object.entries(cfg.rules)
      .filter(([, sev]) => sev === "off")
      .map(([rule]) => rule);
    findings.push({
      id: `DOC:disabled-rules:${cfg.configPath}`,
      level: "mention",
      artifact: cfg.configPath,
      summary: `${cfg.configPath} disables ${disabled.length} Veristack rule(s): ${disabled.join(", ")}.`,
      fix: "Re-enable disabled rules to run Veristack at full rigidity (--strict).",
    });
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
