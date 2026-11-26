import { spawnSync } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import type { DiscoveredRepo } from "../discover.ts";
import type { Finding } from "../types.ts";

export interface FormalCheckEntry {
  id: string;
  specFile: string;
  coveredPaths: string[];
  syncCommit: string;
  contentHash?: string;
  bounds?: string;
  kind?: "formal" | "contract";
}

function computeFormalContentHash(repoRoot: string, specFile: string, coveredPaths: readonly string[]): string {
  const hasher = crypto.createHash("sha256");
  const all = [specFile, ...coveredPaths].sort();
  for (const rel of all) {
    const abs = path.join(repoRoot, rel);
    hasher.update(rel);
    hasher.update("\0");
    if (fs.existsSync(abs)) hasher.update(fs.readFileSync(abs));
    hasher.update("\0");
  }
  return hasher.digest("hex");
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function parseEntries(rawList: unknown, kind: "formal" | "contract"): FormalCheckEntry[] {
  if (!Array.isArray(rawList)) return [];
  const entries: FormalCheckEntry[] = [];
  for (const raw of rawList) {
    if (!isRecord(raw)) continue;
    const id = typeof raw.id === "string" ? raw.id : "unknown";
    const fileField = kind === "contract" ? raw.artifactFile ?? raw.specFile : raw.specFile;
    const specFile = typeof fileField === "string" ? fileField.trim() : "";
    const syncCommit = typeof raw.syncCommit === "string" ? raw.syncCommit.trim() : "";
    const coveredPaths = Array.isArray(raw.coveredPaths)
      ? raw.coveredPaths.filter((p): p is string => typeof p === "string" && p.trim().length > 0)
      : [];
    const bounds = typeof raw.bounds === "string" ? raw.bounds : undefined;
    const contentHash = typeof raw.contentHash === "string" ? raw.contentHash.trim() : undefined;
    entries.push({ id, specFile, coveredPaths, syncCommit, contentHash, bounds, kind });
  }
  return entries;
}

function parseFormalChecks(repo: DiscoveredRepo): { planRel: string; entries: FormalCheckEntry[]; error?: string } | null {
  const planFile = repo.files.find(
    (f) => f.rel === ".verification/control-plan.json" || f.rel === "control-plan.json",
  );
  if (!planFile) return null;
  try {
    const parsed: unknown = JSON.parse(planFile.content);
    if (!isRecord(parsed)) return { planRel: planFile.rel, entries: [], error: `${planFile.rel} must be a JSON object.` };
    const entries = [
      ...parseEntries(parsed.formalChecks, "formal"),
      ...parseEntries(parsed.contractChecks, "contract"),
    ];
    const hasFormalKey = "formalChecks" in parsed || "contractChecks" in parsed;
    const hasControlsOnly = Array.isArray(parsed.controls) && parsed.controls.length > 0 && !hasFormalKey;
    if (entries.length === 0) {
      if (hasControlsOnly) return null;
      return {
        planRel: planFile.rel,
        entries: [],
        error: `${planFile.rel} declares 0 recognized formalChecks/contractChecks entries (empty control plan).`,
      };
    }
    return { planRel: planFile.rel, entries };
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    return { planRel: planFile.rel, entries: [], error: `Malformed JSON in ${planFile.rel}: ${msg}` };
  }
}

export function auditFormalSync(repo: DiscoveredRepo): Finding[] {
  if (!fs.existsSync(repo.root)) {
    return [{
      id: `FS:missing-root:${repo.root}`,
      rule: "formal-plan-malformed",
      category: "oracle-lock",
      rung: "R5",
      severity: "error",
      file: repo.root,
      line: 1,
      message: `Target repository directory '${repo.root}' does not exist.`,
      fix: "Pass an existing repository root directory to formal-sync.",
    }];
  }
  const parsed = parseFormalChecks(repo);
  if (!parsed) return [];
  if (parsed.error) {
    return [
      {
        id: `FS:malformed:${parsed.planRel}`,
        rule: "formal-plan-malformed",
        category: "oracle-lock",
        rung: "R5",
        severity: "error",
        file: parsed.planRel,
        line: 1,
        message: parsed.error,
        fix: `Fix JSON syntax in ${parsed.planRel}; formal sync fails closed on unreadable control plans.`,
      },
    ];
  }
  if (parsed.entries.length === 0) return [];

  const findings: Finding[] = [];
  const allPathSet = new Set(repo.allRelPaths);

  for (const entry of parsed.entries) {
    const isContract = entry.kind === "contract";
    const label = isContract ? "Contract check" : "Formal check";
    if (!entry.specFile || !allPathSet.has(entry.specFile)) {
      findings.push({
        id: `FS:missing:${entry.id}`,
        rule: isContract ? "contract-artifact-missing" : "formal-spec-missing",
        category: "oracle-lock",
        rung: isContract ? "R3" : "R5",
        severity: "error",
        file: parsed.planRel,
        line: 1,
        message: `${label} '${entry.id}' references missing artifact '${entry.specFile}'.`,
        fix: isContract
          ? "Regenerate the contract/OpenAPI/index baseline or update contractChecks[].artifactFile in the control plan."
          : "Restore the formal spec or update formalChecks[].specFile in the control plan.",
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

    if (entry.coveredPaths.length === 0) {
      findings.push({
        id: `FS:empty-covered:${entry.id}`,
        rule: "formal-sync-empty-covered-paths",
        category: "oracle-lock",
        rung: isContract ? "R3" : "R5",
        severity: "error",
        file: parsed.planRel,
        line: 1,
        message: `${label} '${entry.id}' declares empty coveredPaths, which disables drift detection.`,
        fix: "List all production paths governed by this formal/contract spec in coveredPaths.",
      });
      continue;
    }

    const missingCovered = entry.coveredPaths.filter((p) => !allPathSet.has(p));
    if (missingCovered.length > 0) {
      findings.push({
        id: `FS:missing-covered:${entry.id}`,
        rule: "formal-covered-path-missing",
        category: "oracle-lock",
        rung: isContract ? "R3" : "R5",
        severity: "error",
        file: parsed.planRel,
        line: 1,
        message: `${label} '${entry.id}' references missing covered path(s): ${missingCovered.join(", ")}.`,
        fix: "Restore the covered paths or update coveredPaths in the control plan and re-verify.",
      });
      continue;
    }

    const isGitRepo = spawnSync("git", ["-C", repo.root, "rev-parse", "--git-dir"], { encoding: "utf8" }).status === 0;
    if (isGitRepo) {
      const ancestor = spawnSync("git", ["-C", repo.root, "merge-base", "--is-ancestor", entry.syncCommit, "HEAD"], {
        encoding: "utf8",
      });
      if (ancestor.status !== 0) {
        const isShallow =
          (spawnSync("git", ["-C", repo.root, "rev-parse", "--is-shallow-repository"], { encoding: "utf8" }).stdout ?? "")
            .trim() === "true";
        findings.push({
          id: `FS:unknown-commit:${entry.id}`,
          rule: "formal-sync-unknown-commit",
          category: "oracle-lock",
          rung: "R5",
          severity: "error",
          file: parsed.planRel,
          line: 1,
          message: isShallow
            ? `Formal check '${entry.id}' syncCommit '${entry.syncCommit.slice(0, 7)}' is outside shallow clone history — failing closed.`
            : `Formal check '${entry.id}' syncCommit '${entry.syncCommit}' is not an ancestor of HEAD.`,
          fix: "Re-verify the formal model against HEAD and advance syncCommit to a commit on the current branch.",
        });
        continue;
      }
    }

    if (entry.contentHash) {
      const actualHash = computeFormalContentHash(repo.root, entry.specFile, entry.coveredPaths);
      if (actualHash !== entry.contentHash) {
        findings.push({
          id: `FS:hash-drift:${entry.id}`,
          rule: isContract ? "contract-artifact-stale" : "formal-spec-stale",
          category: "oracle-lock",
          rung: isContract ? "R3" : "R5",
          severity: "error",
          file: entry.specFile,
          line: 1,
          message: `${label} '${entry.id}' contentHash mismatch (spec or covered code changed since last verified hash).`,
          fix: `Re-run the formal/contract verifier and update contentHash to '${actualHash}'.`,
        });
      }
      continue;
    }

    const watchedPaths = [...new Set([entry.specFile, ...entry.coveredPaths])];
    const dirtyRes = spawnSync("git", ["-C", repo.root, "status", "--porcelain", "--", ...watchedPaths], {
      encoding: "utf8",
    });
    const dirtyLines = (dirtyRes.stdout ?? "").split(/\r?\n/).map((l) => l.trim()).filter(Boolean);
    if (dirtyLines.length > 0) {
      findings.push({
        id: `FS:dirty:${entry.id}`,
        rule: isContract ? "contract-artifact-stale" : "formal-spec-stale",
        category: "oracle-lock",
        rung: isContract ? "R3" : "R5",
        severity: "error",
        file: entry.specFile,
        line: 1,
        message: `${label} '${entry.id}' has uncommitted edits on covered path(s): ${dirtyLines.join(", ")}.`,
        fix: "Re-verify covered code, commit or update contentHash, and advance syncCommit.",
      });
      continue;
    }
    const logRes = spawnSync(
      "git",
      ["-C", repo.root, "log", "--oneline", `${entry.syncCommit}..HEAD`, "--", ...watchedPaths],
      { encoding: "utf8" },
    );
    const commits = (logRes.stdout ?? "")
      .split(/\r?\n/)
      .map((line) => line.trim())
      .filter(Boolean);

    if (commits.length > 0) {
      findings.push({
        id: `FS:stale:${entry.id}`,
        rule: isContract ? "contract-artifact-stale" : "formal-spec-stale",
        category: "oracle-lock",
        rung: isContract ? "R3" : "R5",
        severity: "error",
        file: entry.specFile,
        line: 1,
        message: `${label} '${entry.id}' is stale: ${commits.length} commit(s) modified covered code since ${entry.syncCommit.slice(0, 7)} (${commits[0]}).`,
        fix: isContract
          ? "Regenerate/verify the OpenAPI baseline, consumer manifest, or DB index file against HEAD and advance syncCommit."
          : "Re-audit covered paths against the formal spec, rerun the verifier, prove a scratch break fails, and advance syncCommit.",
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
