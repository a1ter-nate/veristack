import fs from "node:fs";
import path from "node:path";
import { lineOf, maskCode, pathHelpers, runGitClean } from "@veristack/plugin";

export interface SoundinessSite {
  file: string;
  line: number;
  kind:
    | "eval"
    | "dynamic-import"
    | "reflection"
    | "proxy"
    | "unsafe-cast"
    | "rust-unsafe"
    | "python-dynamic-exec"
    | "dynamic-sql";
  snippet: string;
}

export interface FileEmpiricalRisk {
  file: string;
  relativeChurn: number;
  complexity: number;
  hotspotPriority: number;
  nfix: number;
  distinctAuthors: number;
  majorOwnerPct: number;
}

export interface EmpiricalPrRiskReport {
  changeEntropy: number;
  totalNfix: number;
  maxHotspotPriority: number;
  ownershipDiffusionFiles: number;
  shallowHistoryFallback: boolean;
  files: FileEmpiricalRisk[];
}

const SOUNDINESS_RULES: ReadonlyArray<{ kind: SoundinessSite["kind"]; re: RegExp; langs?: readonly string[] }> = [
  { kind: "eval", re: /\b(?:eval\s*\(|new\s+Function\s*\()/g, langs: ["typescript", "javascript"] },
  { kind: "dynamic-import", re: /\bimport\s*\(\s*(?!["'])/g, langs: ["typescript", "javascript"] },
  { kind: "reflection", re: /\bReflect\s*\.\s*[A-Za-z_]\w*\s*\(/g, langs: ["typescript", "javascript"] },
  { kind: "proxy", re: /\bnew\s+Proxy\s*\(/g, langs: ["typescript", "javascript"] },
  { kind: "unsafe-cast", re: /\bas\s+unknown\s+as\b|\bas\s+any\b/g, langs: ["typescript"] },
  { kind: "rust-unsafe", re: /\bunsafe\s*(?:\{|fn\b|impl\b)/g, langs: ["rust"] },
  { kind: "python-dynamic-exec", re: /\b(?:eval|exec|getattr|setattr)\s*\(/g, langs: ["python"] },
  { kind: "dynamic-sql", re: /`\s*(?:SELECT|INSERT|UPDATE|DELETE)\b[^`]*\$\{/gi, langs: ["typescript", "javascript"] },
];

export function collectSoundinessLedger(repoRoot: string, relFiles: readonly string[]): SoundinessSite[] {
  if (!repoRoot) throw new Error("repoRoot is required.");
  const sites: SoundinessSite[] = [];
  const cap = 80;
  for (const rel of relFiles) {
    if (sites.length >= cap) break;
    const lang = pathHelpers.detectLanguage(rel);
    if (!lang || pathHelpers.isTestFilePath(rel)) continue;
    const abs = path.join(repoRoot, rel);
    if (!fs.existsSync(abs)) continue;
    let raw: string;
    try { raw = fs.readFileSync(abs, "utf8"); } catch { continue; }
    const masked = maskCode(raw, lang, true);
    for (const rule of SOUNDINESS_RULES) {
      if (rule.langs && !rule.langs.includes(lang)) continue;
      const target = rule.kind === "dynamic-sql" ? raw : masked;
      for (const m of target.matchAll(rule.re)) {
        if (sites.length >= cap) break;
        const idx = m.index ?? 0;
        const line = lineOf(raw, idx);
        sites.push({ file: rel, line, kind: rule.kind, snippet: raw.slice(idx, Math.min(raw.length, idx + 48)).replace(/\s+/g, " ").trim() });
      }
    }
  }
  return sites;
}

function estimateFileComplexity(raw: string): number {
  const branches = raw.match(/\b(?:if|else\s+if|for|while|case|catch|match)\b|&&|\|\||\?/g);
  return 1 + (branches ? branches.length : 0);
}

function queryFileGitRisk(repoRoot: string, rel: string): { nfix: number; distinctAuthors: number; majorOwnerPct: number; commits: number } {
  const log = runGitClean(repoRoot, ["log", "-n", "120", "--format=%ae\t%s", "--", rel], { timeout: 3000 });
  if (log.status !== 0 || !log.stdout.trim()) return { nfix: 0, distinctAuthors: 0, majorOwnerPct: 100, commits: 0 };
  const lines = log.stdout.trim().split(/\r?\n/).filter(Boolean);
  let nfix = 0;
  const authorCounts = new Map<string, number>();
  for (const row of lines) {
    const [author = "", subject = ""] = row.split("\t");
    if (author) authorCounts.set(author, (authorCounts.get(author) ?? 0) + 1);
    if (/\b(?:fix|bug|hotfix|revert|regression|patch)\b/i.test(subject)) nfix += 1;
  }
  let topCount = 0;
  for (const c of authorCounts.values()) if (c > topCount) topCount = c;
  const total = lines.length;
  const majorOwnerPct = total > 0 ? Math.round((topCount / total) * 100) : 100;
  return { nfix, distinctAuthors: authorCounts.size, majorOwnerPct, commits: total };
}

export function computeEmpiricalPrRisk(
  repoRoot: string,
  changed: ReadonlyArray<{ file: string; added: number; deleted: number }>,
): EmpiricalPrRiskReport {
  if (!repoRoot) throw new Error("repoRoot is required.");
  const nonZero = changed.filter((c) => c.added + c.deleted > 0);
  const totalChurn = nonZero.reduce((sum, c) => sum + c.added + c.deleted, 0);
  let entropy = 0;
  if (nonZero.length > 1 && totalChurn > 0) {
    for (const c of nonZero) {
      const p = (c.added + c.deleted) / totalChurn;
      if (p > 0) entropy -= p * Math.log2(p);
    }
    entropy = Number((entropy / Math.log2(nonZero.length)).toFixed(3));
  }
  const files: FileEmpiricalRisk[] = [];
  let totalNfix = 0;
  let maxHotspotPriority = 0;
  let ownershipDiffusionFiles = 0;
  let maxObservedCommits = 0;
  for (const c of changed.slice(0, 40)) {
    const abs = path.join(repoRoot, c.file);
    let totalLines = 1;
    let complexity = 1;
    if (fs.existsSync(abs)) {
      try {
        const raw = fs.readFileSync(abs, "utf8");
        totalLines = Math.max(1, raw.split(/\r?\n/).length);
        complexity = estimateFileComplexity(raw);
      } catch { void 0; }
    }
    const relativeChurn = Number(((c.added + c.deleted) / totalLines).toFixed(3));
    const hotspotPriority = Number((complexity * Math.min(2, relativeChurn)).toFixed(2));
    const gitRisk = queryFileGitRisk(repoRoot, c.file);
    if (gitRisk.commits > maxObservedCommits) maxObservedCommits = gitRisk.commits;
    totalNfix += gitRisk.nfix;
    if (hotspotPriority > maxHotspotPriority) maxHotspotPriority = hotspotPriority;
    if (gitRisk.distinctAuthors >= 3 && gitRisk.majorOwnerPct < 60) ownershipDiffusionFiles += 1;
    files.push({
      file: c.file, relativeChurn, complexity, hotspotPriority,
      nfix: gitRisk.nfix, distinctAuthors: gitRisk.distinctAuthors, majorOwnerPct: gitRisk.majorOwnerPct,
    });
  }
  files.sort((a, b) => b.hotspotPriority - a.hotspotPriority || b.nfix - a.nfix);
  return {
    changeEntropy: entropy,
    totalNfix,
    maxHotspotPriority,
    ownershipDiffusionFiles,
    shallowHistoryFallback: changed.length > 0 && maxObservedCommits <= 1,
    files,
  };
}
