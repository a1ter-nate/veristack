import fs from "node:fs";
import path from "node:path";

interface ParsedSemver {
  prefix: "" | "~" | "^";
  major: number;
  minor: number;
  patch: number;
}

const PINNED_SEMVER_RE = /^([~^]?)(\d+)\.(\d+)\.(\d+)$/;

function parseSimpleSemver(spec: string): ParsedSemver | null {
  const m = PINNED_SEMVER_RE.exec(spec.trim());
  if (!m?.[2] || !m[3] || !m[4]) return null;
  const prefix = (m[1] ?? "") as "" | "~" | "^";
  return {
    prefix,
    major: Number(m[2]),
    minor: Number(m[3]),
    patch: Number(m[4]),
  };
}

function prefixRank(prefix: "" | "~" | "^"): number {
  if (prefix === "") return 0;
  if (prefix === "~") return 1;
  return 2;
}

export function isSafePinnedToolUpgrade(baseSpec: string, headSpec: string): boolean {
  if (!baseSpec || !headSpec) return false;
  const b = parseSimpleSemver(baseSpec);
  const h = parseSimpleSemver(headSpec);
  if (!b || !h) return false;
  if (prefixRank(h.prefix) > prefixRank(b.prefix)) return false;
  if (h.major !== b.major) return h.major > b.major;
  if (h.minor !== b.minor) return h.minor > b.minor;
  return h.patch > b.patch;
}

interface ManifestApprovalEntry {
  approvedBy?: string;
  reason?: string;
  baseRef?: string;
  files?: string[];
}

export function isManifestChangeApproved(repoRoot: string, baseRef: string): boolean {
  if (process.env.VSTACK_ALLOW_MANIFEST_CHANGE === "1") return true;
  if (!repoRoot || !baseRef) return false;
  const approvalPath = path.join(repoRoot, ".verification", "manifest-approvals.json");
  if (!fs.existsSync(approvalPath) || !fs.statSync(approvalPath).isFile()) return false;
  try {
    const parsed = JSON.parse(fs.readFileSync(approvalPath, "utf8")) as { approvals?: ManifestApprovalEntry[] };
    const list = Array.isArray(parsed.approvals) ? parsed.approvals : [];
    return list.some(
      (entry) =>
        typeof entry.approvedBy === "string" &&
        entry.approvedBy.trim().length > 1 &&
        typeof entry.reason === "string" &&
        entry.reason.trim().length >= 8 &&
        (!entry.baseRef || entry.baseRef === baseRef),
    );
  } catch {
    return false;
  }
}
