import type { DiscoveredRepo, ScannedFile } from "../discover.ts";
import { lineOf, maskCode } from "../test-lexical.ts";
import type { Finding } from "../types.ts";

interface ChokePointRule {
  pattern: string;
  languages?: string[];
  allowPaths?: string[];
  replacement: string;
  reason?: string;
}

const ACTION_USES_LINE = /^\s*-?\s*uses:\s*([A-Za-z0-9_.-]+\/[A-Za-z0-9_./-]+)@([^\s#]+)/;
const DOCKER_USES_LINE = /^\s*-?\s*uses:\s*docker:\/\/([^\s#]+)/;
const HEX_40 = /^[0-9a-f]{40}$/i;
const CURL_PIPE_SHELL = /\b(?:curl|wget)\b[^\n|]*\|\s*(?:sudo\s+)?(?:sh|bash|zsh)\b/i;

function push(
  findings: Finding[],
  file: string,
  line: number,
  rule: string,
  rung: Finding["rung"],
  severity: Finding["severity"],
  message: string,
  fix: string,
): void {
  findings.push({ id: `IMM:${rule}:${file}:${line}`, rule, category: "ci-hygiene", rung, severity, file, line, message, fix });
}

function loadChokePoints(repo: DiscoveredRepo, findings: Finding[]): ChokePointRule[] {
  const cfg = repo.files.find((f) => /(?:^|\/)\.verification\/chokepoints\.json$/i.test(f.rel));
  if (!cfg) return [];
  try {
    const parsed = JSON.parse(cfg.content) as { rules?: ChokePointRule[] };
    if (!parsed || typeof parsed !== "object" || !Array.isArray(parsed.rules)) {
      push(findings, cfg.rel, 1, "chokepoints-invalid-json", "R0", "error", `${cfg.rel} must contain a JSON object with a 'rules' array.`, "Fix .verification/chokepoints.json schema so choke-point enforcement cannot fail open.");
      return [];
    }
    return parsed.rules;
  } catch {
    push(findings, cfg.rel, 1, "chokepoints-invalid-json", "R0", "error", `${cfg.rel} contains invalid JSON — failing closed.`, "Fix JSON syntax in .verification/chokepoints.json.");
    return [];
  }
}

function findTokenOffsets(text: string, token: string): number[] {
  const hits: number[] = [];
  let pos = text.indexOf(token);
  while (pos >= 0) {
    const before = pos > 0 ? text[pos - 1] ?? "" : "";
    const after = pos + token.length < text.length ? text[pos + token.length] ?? "" : "";
    if (!/[A-Za-z0-9_]/.test(before) && !/[A-Za-z0-9_]/.test(after)) hits.push(pos);
    pos = text.indexOf(token, pos + token.length);
  }
  return hits;
}

function auditChokePoints(repo: DiscoveredRepo, findings: Finding[]): void {
  const rules = loadChokePoints(repo, findings);
  if (rules.length === 0) return;

  const compiled = rules
    .filter((r) => typeof r.pattern === "string" && r.pattern.length > 0)
    .map((r) => ({
      rule: r,
      allowSet: (r.allowPaths ?? []).map((p) => p.replace(/^\/+/, "")),
      langSet: r.languages ? new Set(r.languages) : null,
    }));

  for (const file of repo.files) {
    if (!file.language || file.isTest) continue;
    const masked = maskCode(file.content, file.language);
    for (const c of compiled) {
      if (c.langSet && !c.langSet.has(file.language)) continue;
      if (c.allowSet.some((prefix) => file.rel === prefix || file.rel.startsWith(prefix))) continue;
      for (const offset of findTokenOffsets(masked, c.rule.pattern)) {
        push(
          findings, file.rel, lineOf(file.content, offset), "chokepoint-banned-primitive", "R0", "error",
          `Direct use of banned primitive '${c.rule.pattern}' bypasses the repo choke point (${c.rule.reason ?? "enforced via .verification/chokepoints.json"}).`,
          `Use '${c.rule.replacement}' instead of '${c.rule.pattern}'.`,
        );
      }
    }
  }
}

function auditWorkflowImmuneSupplyChain(file: ScannedFile, findings: Finding[]): void {
  const lines = file.content.split(/\r?\n/);

  if (file.rel.startsWith(".github/workflows/") && !/^\s*permissions:/m.test(file.content)) {
    push(
      findings, file.rel, 1, "ci-missing-explicit-permissions", "R0", "warn",
      "GitHub Actions workflow omits top-level 'permissions:' block (75% of audited OSS titans enforce least privilege).",
      "Add top-level 'permissions: { contents: read }' and grant narrower write scopes only on specific release jobs.",
    );
  }

  for (let i = 0; i < lines.length; i++) {
    const raw = lines[i] ?? "";
    if (!/^\s*#/.test(raw) && CURL_PIPE_SHELL.test(raw)) {
      push(
        findings, file.rel, i + 1, "ci-curl-pipe-shell", "R0", "error",
        "Workflow pipes remote download directly into a shell interpreter (curl/wget | sh).",
        "Download a pinned checksum-verified release artifact or use a SHA-pinned action instead of piping into sh.",
      );
    }
    const dm = DOCKER_USES_LINE.exec(raw);
    if (dm?.[1] && !/@sha256:[0-9a-f]{64}$/i.test(dm[1])) {
      push(
        findings, file.rel, i + 1, "ci-unpinned-third-party-action", "R0", "warn",
        `Docker action 'docker://${dm[1]}' is not pinned to an immutable @sha256 digest.`,
        "Pin docker:// actions with '@sha256:<64-hex-digest>' instead of mutable tags like :latest.",
      );
      continue;
    }
    const m = ACTION_USES_LINE.exec(raw);
    if (!m) continue;
    const action = m[1] ?? "";
    const ref = m[2] ?? "";
    if (HEX_40.test(ref)) continue;
    const isFirstParty = /^(?:actions|github)\//i.test(action);
    if (!isFirstParty) {
      push(
        findings, file.rel, i + 1, "ci-unpinned-third-party-action", "R0", "warn",
        `Third-party GitHub Action '${action}@${ref}' is not pinned to a full 40-char commit SHA.`,
        `Pin '${action}@<40-char-commit-sha> # ${ref}' to prevent supply-chain tag hijacking.`,
      );
    }
  }

  const hasDeployOrWrite = /\b(?:id-token:\s*write|packages:\s*write|deployments:\s*write|vercel\s+deploy|npm\s+publish|docker\s+push|aws-actions\/configure-aws-credentials)\b/i.test(file.content);
  if (hasDeployOrWrite && /uses:\s*actions\/checkout@/i.test(file.content) && !/persist-credentials:\s*false/i.test(file.content)) {
    push(
      findings, file.rel, 1, "ci-checkout-missing-persist-creds-false", "R0", "warn",
      "Workflow with privileged deploy/OIDC steps uses actions/checkout without 'persist-credentials: false'.",
      "Pass 'with: { persist-credentials: false }' to actions/checkout so GITHUB_TOKEN is not left in .git/config.",
    );
  }
}

function auditLinterImmuneConfigs(file: ScannedFile, findings: Finding[]): void {
  const base = file.rel.split("/").pop()?.toLowerCase() ?? "";

  if (base === "directory.build.props" && !file.rel.startsWith("templates/")) {
    const hasAnalyzers =
      /<EnableNETAnalyzers>\s*true\s*<\/EnableNETAnalyzers>/i.test(file.content) ||
      /<AnalysisLevel>\s*latest/i.test(file.content);
    const hasTreatWarn = /<TreatWarningsAsErrors>\s*true\s*<\/TreatWarningsAsErrors>/i.test(file.content);
    if (!hasAnalyzers || !hasTreatWarn) {
      push(
        findings, file.rel, 1, "immune-dotnet-missing-analyzers", "R1", "warn",
        "Directory.Build.props is missing <EnableNETAnalyzers>true</EnableNETAnalyzers> or <TreatWarningsAsErrors>true</TreatWarningsAsErrors>.",
        "Enable built-in .NET analyzers at AnalysisLevel=latest and enforce TreatWarningsAsErrors=true.",
      );
    }
  }

  if (base === ".golangci.yml" || base === ".golangci.yaml") {
    const required = ["errcheck", "bodyclose", "gosec"];
    const missing = required.filter((r) => findTokenOffsets(file.content, r).length === 0);
    if (missing.length > 0) {
      push(
        findings, file.rel, 1, "immune-go-missing-safety-linters", "R1", "warn",
        `.golangci.yml is missing critical Go safety linters enforced by cloud-native titans: ${missing.join(", ")}.`,
        `Enable ${missing.join(", ")} (plus exhaustive, sqlclosecheck, bidichk) in .golangci.yml.`,
      );
    }
  }
}

export function analyzeImmuneSystemGates(repo: DiscoveredRepo): Finding[] {
  const findings: Finding[] = [];
  auditChokePoints(repo, findings);

  for (const file of repo.files) {
    if (file.isWorkflow) {
      auditWorkflowImmuneSupplyChain(file, findings);
    } else {
      auditLinterImmuneConfigs(file, findings);
    }
  }

  return findings;
}
