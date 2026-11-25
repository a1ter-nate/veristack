import { spawnSync } from "node:child_process";
import type { DiscoveredRepo } from "../discover.ts";
import type { Finding } from "../types.ts";

export interface FormalCheckEntry {
  id: string;
  specFile: string;
  coveredPaths: string[];
  syncCommit: string;
  bounds?: string;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function parseFormalChecks(repo: DiscoveredRepo): { planRel: string; entries: FormalCheckEntry[] } | null {
  const planFile = repo.files.find(
    (f) => f.rel === ".verification/control-plan.json" || f.rel === "control-plan.json",
  );
  if (!planFile) return null;
  try {
    const parsed: unknown = JSON.parse(planFile.content);
    if (!isRecord(parsed) || !Array.isArray(parsed.formalChecks)) return null;
    const entries: FormalCheckEntry[] = [];
    for (const raw of parsed.formalChecks) {
      if (!isRecord(raw)) continue;
      const id = typeof raw.id === "string" ? raw.id : "unknown";
      const specFile = typeof raw.specFile === "string" ? raw.specFile.trim() : "";
      const syncCommit = typeof raw.syncCommit === "string" ? raw.syncCommit.trim() : "";
      const coveredPaths = Array.isArray(raw.coveredPaths)
        ? raw.coveredPaths.filter((p): p is string => typeof p === "string" && p.trim().length > 0)
        : [];
      const bounds = typeof raw.bounds === "string" ? raw.bounds : undefined;
      entries.push({ id, specFile, coveredPaths, syncCommit, bounds });
    }
    return { planRel: planFile.rel, entries };
  } catch {
    return null;
  }
}

export function auditFormalSync(repo: DiscoveredRepo): Finding[] {
  const parsed = parseFormalChecks(repo);
  if (!parsed || parsed.entries.length === 0) return [];

  const findings: Finding[] = [];
  const allPathSet = new Set(repo.allRelPaths);

  for (const entry of parsed.entries) {
    if (!entry.specFile || !allPathSet.has(entry.specFile)) {
      findings.push({
        id: `FS:missing:${entry.id}`,
        rule: "formal-spec-missing",
        category: "oracle-lock",
        rung: "R5",
        severity: "error",
        file: parsed.planRel,
        line: 1,
        message: `Formal check '${entry.id}' references missing spec '${entry.specFile}'.`,
        fix: "Restore the formal spec or update formalChecks[].specFile in the control plan.",
      });
      continue;
    }

    if (!entry.syncCommit || entry.syncCommit.startsWith("-") || !/^[0-9a-fA-F]{7,40}$/.test(entry.syncCommit)) {
      findings.push({
        id: `FS:bad-commit:${entry.id}`,
        rule: "formal-sync-invalid-commit",
        category: "oracle-lock",
        rung: "R5",
        severity: "error",
        file: parsed.planRel,
        line: 1,
        message: `Formal check '${entry.id}' has invalid syncCommit '${entry.syncCommit}'.`,
        fix: "Record the exact 7-40 char git commit SHA where the formal model was last verified against covered code.",
      });
      continue;
    }

    if (entry.coveredPaths.length === 0) continue;

    const revCheck = spawnSync("git", ["-C", repo.root, "cat-file", "-e", `${entry.syncCommit}^{commit}`], {
      encoding: "utf8",
    });
    if (revCheck.status !== 0) {
      findings.push({
        id: `FS:unknown-commit:${entry.id}`,
        rule: "formal-sync-unknown-commit",
        category: "oracle-lock",
        rung: "R5",
        severity: "warn",
        file: parsed.planRel,
        line: 1,
        message: `Formal check '${entry.id}' syncCommit '${entry.syncCommit}' not found in local git history (shallow clone or rebased).`,
        fix: "Re-verify the formal model against HEAD and update syncCommit.",
      });
      continue;
    }

    const logRes = spawnSync(
      "git",
      ["-C", repo.root, "log", "--oneline", `${entry.syncCommit}..HEAD`, "--", ...entry.coveredPaths],
      { encoding: "utf8" },
    );
    const commits = (logRes.stdout ?? "")
      .split(/\r?\n/)
      .map((line) => line.trim())
      .filter(Boolean);

    if (commits.length > 0) {
      findings.push({
        id: `FS:stale:${entry.id}`,
        rule: "formal-spec-stale",
        category: "oracle-lock",
        rung: "R5",
        severity: "error",
        file: entry.specFile,
        line: 1,
        message: `Formal check '${entry.id}' is stale: ${commits.length} commit(s) modified covered code since ${entry.syncCommit.slice(0, 7)} (${commits[0]}).`,
        fix: "Re-audit covered paths against the formal spec, rerun the verifier, prove a scratch break fails, and advance syncCommit.",
      });
    }
  }

  return findings;
}

export function formatFormalSyncReport(findings: readonly Finding[]): string {
  if (findings.length === 0) return "formal-sync: all tracked formal checks are in sync with HEAD.";
  const lines = [`formal-sync: ${findings.length} drift/integrity issue(s) found.`];
  for (const f of findings) {
    lines.push(`  - [${f.severity.toUpperCase()}] ${f.rule} ${f.file} — ${f.message}\n      Fix: ${f.fix}`);
  }
  return lines.join("\n");
}
