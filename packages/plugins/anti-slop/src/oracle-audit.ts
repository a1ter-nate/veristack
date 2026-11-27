import path from "node:path";
import type { DiscoveredRepo } from "@veristack/plugin";
import type { Finding } from "@veristack/plugin";

const INSTRUCTION_NAMES = new Set(["agents.md", "claude.md", "gemini.md", "skill.md"]);
const ORACLE_NO_EDIT_TOPIC =
  /\b(?:oracle|gherkin|feature files?|acceptance tests?|contracts\.lock)\b|(?:features|tests\/acceptance)\/|\.feature\b/i;
const ORACLE_LOCK_VERB =
  /\b(?:read[- ]only|locked|immutable)\b|\b(?:do not|don't|must not|never)\s+(?:be\s+)?(?:edit|modify|change|rewrite|delete|touch)(?:ed)?\b/i;
const WEAKEN_FORBID =
  /\b(?:never weaken|never skip|do not skip|must not (?:weaken|skip|delete))\b.{0,40}\b(?:test|check|baseline|ratchet|floor)\b/i;
const WEAKEN_ALLOW = /\b(?:skip|delete|weaken|disable)\s+tests?\s+to\s+(?:get\s+a\s+)?pass\b/i;

function globToRegex(pattern: string): RegExp | undefined {
  let value = pattern.trim().replace(/\\ /g, " ").replace(/^\/+/, "");
  if (!value || value.startsWith("!")) return undefined;
  if (value.endsWith("/")) value += "**";
  const hasSlash = value.includes("/");
  let body = "";
  for (let i = 0; i < value.length; i++) {
    const ch = value[i] ?? "";
    if (ch === "*") {
      if (value[i + 1] === "*") {
        while (value[i + 1] === "*") i += 1;
        if (value[i + 1] === "/") {
          i += 1;
          body += "(?:.*/)?";
        } else {
          body += ".*";
        }
      } else {
        body += "[^/]*";
      }
    } else if (ch === "?") {
      body += "[^/]";
    } else {
      body += ch.replace(/[\\^$+?.()|{}[\]]/g, "\\$&");
    }
  }
  return new RegExp(`${hasSlash ? "^" : "(?:^|.*/)"}${body}$`);
}

function parseCodeowners(text: string): Array<{ regex: RegExp; owners: string[] }> {
  const rules: Array<{ regex: RegExp; owners: string[] }> = [];
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || line.startsWith("#")) continue;
    const [pattern, ...rest] = line.split(/\s+/);
    const owners = rest.filter((item) => item.startsWith("@") || item.includes("@"));
    if (!pattern || owners.length === 0) continue;
    const regex = globToRegex(pattern);
    if (regex) rules.push({ regex, owners });
  }
  return rules;
}

function auditOracleCodeowners(
  repo: DiscoveredRepo,
  oracleArtifacts: readonly string[],
  findings: Finding[],
): void {
  if (oracleArtifacts.length === 0) return;
  const codeownersFiles = repo.files.filter((f) => path.posix.basename(f.rel).toLowerCase() === "codeowners");
  const ownerRules = codeownersFiles.flatMap((f) => parseCodeowners(f.content));
  if (ownerRules.length === 0) return;
  for (const artifact of oracleArtifacts) {
    const normalized = artifact.replace(/\\/g, "/").replace(/^\.\//, "");
    if (ownerRules.some((r) => r.regex.test(normalized))) continue;
    findings.push({
      id: `OL:unowned:${artifact}`,
      rule: "oracle-lock-unowned",
      category: "oracle-lock",
      rung: "R0",
      severity: "warn",
      file: artifact,
      line: 1,
      message: `Oracle/acceptance artifact ${artifact} is not covered by any CODEOWNERS rule.`,
      fix: "Add an explicit CODEOWNERS entry protecting acceptance specs and contract locks.",
    });
  }
}

function auditInstructionPolicies(
  repo: DiscoveredRepo,
  oracleArtifacts: readonly string[],
  findings: Finding[],
): void {
  const instructionFiles = repo.files.filter((f) =>
    INSTRUCTION_NAMES.has(path.posix.basename(f.rel).toLowerCase()),
  );
  if (instructionFiles.length === 0) return;
  let forbidFile: string | undefined;
  let allowFile: string | undefined;
  let allowLine = 1;
  let hasOracleLockRule = false;
  for (const file of instructionFiles) {
    const lines = file.content.split(/\r?\n/);
    for (let idx = 0; idx < lines.length; idx++) {
      const line = lines[idx] ?? "";
      if (ORACLE_NO_EDIT_TOPIC.test(line) && ORACLE_LOCK_VERB.test(line)) hasOracleLockRule = true;
      if (!forbidFile && WEAKEN_FORBID.test(line)) forbidFile = file.rel;
      if (!allowFile && WEAKEN_ALLOW.test(line)) { allowFile = file.rel; allowLine = idx + 1; }
    }
  }
  if (forbidFile && allowFile) {
    findings.push({
      id: `IC:weaken-conflict:${allowFile}:${allowLine}`,
      rule: "instruction-conflict",
      category: "oracle-lock",
      rung: "R0",
      severity: "error",
      file: allowFile,
      line: allowLine,
      message: `Instruction file ${allowFile} permits weakening/skipping tests, contradicting ${forbidFile}.`,
      fix: "Remove contradictory test-weakening guidance so all agent instructions enforce one deterministic policy.",
    });
  }
  if (oracleArtifacts.length > 0 && !hasOracleLockRule) {
    findings.push({
      id: `OL:missing-no-edit:${instructionFiles[0]?.rel ?? "AGENTS.md"}`,
      rule: "oracle-lock-instruction-missing",
      category: "oracle-lock",
      rung: "R0",
      severity: "warn",
      file: instructionFiles[0]?.rel ?? "AGENTS.md",
      line: 1,
      message: "Acceptance/oracle artifacts exist, but agent instructions do not explicitly mark them read-only.",
      fix: "State in AGENTS.md that implementing agents must not edit locked acceptance specs or contract locks.",
    });
  }
}

export function analyzeOracleAndInstructions(repo: DiscoveredRepo): Finding[] {
  if (!repo.root) throw new Error("Repo root is required.");
  const findings: Finding[] = [];
  if (repo.files.length === 0) return findings;
  const oracleArtifacts = repo.allRelPaths.filter(
    (rel) => /\.feature$/i.test(rel) || /(?:^|\/)tests\/acceptance\//i.test(rel) || /(?:^|\/)contracts\.lock\.json$/i.test(rel),
  );
  auditOracleCodeowners(repo, oracleArtifacts, findings);
  auditInstructionPolicies(repo, oracleArtifacts, findings);
  return findings;
}
