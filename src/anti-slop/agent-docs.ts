import fs from "node:fs";
import path from "node:path";
import type { DiscoveredRepo } from "../discover.ts";
import type { Finding } from "../types.ts";

const AGENT_DOC_BASENAME = /^(?:agents\.md|claude\.md|gemini\.md|review\.md|\.cursorrules|copilot-instructions\.md)$/i;
const MAX_AGENT_DOC_LINES = 400;
const BACKTICK_TOKEN = /`([^`\r\n]+)`/g;
const KNOWN_FILE_EXT = /\.(?:[cm]?[jt]sx?|cs|py|rs|go|jsonc?|ya?ml|toml|sql|sh|bash|md|mdx|bend|csproj|slnx)$/i;
const MECHANICAL_PROHIBITION =
  /\b(?:never|must not|do not|don't|ban|forbid)\s+(?:use|call|import|add|commit|skip|weaken|pipe|disable)\b/i;

function isAgentInstructionFile(rel: string): boolean {
  const norm = rel.replace(/\\/g, "/");
  if (/^(?:examples|templates|tests\/fixtures)\//i.test(norm)) return false;
  const base = path.posix.basename(norm);
  return AGENT_DOC_BASENAME.test(base);
}

function collectTopLevelDirs(repoRoot: string): Set<string> {
  const dirs = new Set<string>();
  try {
    for (const entry of fs.readdirSync(repoRoot, { withFileTypes: true })) {
      if (entry.isDirectory() && entry.name !== ".git" && entry.name !== "node_modules") {
        dirs.add(entry.name);
      }
    }
  } catch {
    return dirs;
  }
  return dirs;
}

export function auditAgentDocs(repo: DiscoveredRepo): Finding[] {
  const findings: Finding[] = [];
  const topDirs = collectTopLevelDirs(repo.root);
  const hasMechanicalEnforcementRegistry = repo.allRelPaths.some((p) =>
    /^\.verification\/(?:chokepoints|escapes)\.json$/i.test(p),
  );

  for (const file of repo.files) {
    if (!isAgentInstructionFile(file.rel)) continue;

    if (file.lines > MAX_AGENT_DOC_LINES) {
      findings.push({
        id: `AD:bloat:${file.rel}:1`,
        rule: "agent-doc-bloat",
        category: "structure",
        rung: "R0",
        severity: "warn",
        file: file.rel,
        line: 1,
        message: `Agent instruction file ${file.rel} has ${file.lines} lines (budget: <= ${MAX_AGENT_DOC_LINES}); oversized instruction files dilute context and compound slop.`,
        fix: "Trim stale prose, move topic details into progressive-disclosure docs, and promote mechanical rules into R0/R1 linters.",
      });
    }

    const lines = file.content.split(/\r?\n/);
    const seenStale = new Set<string>();
    let inFence = false;
    let staleCount = 0;
    let mechanicalProseCount = 0;

    for (let idx = 0; idx < lines.length; idx++) {
      const line = lines[idx] ?? "";
      if (/^\s*```/.test(line)) {
        inFence = !inFence;
        continue;
      }
      if (inFence) continue;

      if (MECHANICAL_PROHIBITION.test(line)) {
        mechanicalProseCount += 1;
      }

      if (staleCount >= 5) continue;
      for (const m of line.matchAll(BACKTICK_TOKEN)) {
        const rawToken = (m[1] ?? "").trim();
        if (!rawToken || /\s|[*?<>:${}()|]|:\/\//.test(rawToken)) continue;
        if (rawToken.startsWith("/") || rawToken.startsWith("~") || rawToken.startsWith("-")) continue;
        const clean = rawToken.replace(/^\.\//, "").split("#")[0]?.split(":")[0] ?? "";
        if (!clean || !clean.includes("/") || clean.endsWith("/")) continue;
        if (!KNOWN_FILE_EXT.test(clean)) continue;

        const firstSegment = clean.split("/")[0] ?? "";
        if (!topDirs.has(firstSegment)) continue;
        if (seenStale.has(clean)) continue;

        const resolved = path.resolve(repo.root, clean);
        if (!resolved.startsWith(`${repo.root}${path.sep}`)) continue;
        if (fs.existsSync(resolved)) continue;
        const siblingResolved = path.resolve(path.dirname(file.abs), clean);
        if (siblingResolved.startsWith(`${repo.root}${path.sep}`) && fs.existsSync(siblingResolved)) continue;

        seenStale.add(clean);
        staleCount += 1;
        findings.push({
          id: `AD:stale-path:${file.rel}:${idx + 1}:${clean}`,
          rule: "agent-doc-stale-path",
          category: "structure",
          rung: "R0",
          severity: "warn",
          file: file.rel,
          line: idx + 1,
          message: `Agent instruction file references missing path '${clean}'; stale knowledge-base pointers cause agents to hallucinate or copy obsolete patterns.`,
          fix: `Update or remove the stale reference to '${clean}' in ${file.rel}.`,
        });
        if (staleCount >= 5) break;
      }
    }

    if (mechanicalProseCount >= 4 && !hasMechanicalEnforcementRegistry) {
      findings.push({
        id: `AD:unpromoted:${file.rel}:1`,
        rule: "agent-doc-unpromoted-rules",
        category: "structure",
        rung: "R1",
        severity: "info",
        file: file.rel,
        line: 1,
        message: `${file.rel} states ${mechanicalProseCount} mechanical prohibition(s) in prose without a .verification/chokepoints.json or escapes.json enforcement registry.`,
        fix: "Run 'vstack circuit run instruction-lint-promoter .' and promote repeatable bans into deterministic R0/R1 linters.",
      });
    }
  }

  return findings;
}
