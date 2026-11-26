import YAML from "yaml";
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

const HEX_40 = /^[0-9a-f]{40}$/i;
const FETCH_TO_SHELL =
  /\b(?:curl|wget)\b[^\n|]*\|\s*(?:sudo\s+(?:-[A-Za-z]+\s+)*)?(?:sh|bash|zsh|python3?|perl|ruby|tee\b[^\n]*\|\s*(?:sh|bash))|\b(?:bash|sh|zsh)\s+<\(\s*(?:curl|wget)\b|\b(?:sh|bash)\s+-c\s+["']?\$\(\s*(?:curl|wget)\b/i;

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

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
    const parsed = JSON.parse(cfg.content) as { rules?: unknown };
    if (!isRecord(parsed) || !Array.isArray(parsed.rules) || parsed.rules.length === 0) {
      push(findings, cfg.rel, 1, "chokepoints-invalid-json", "R0", "error", `${cfg.rel} must contain a non-empty 'rules' array.`, "Fix .verification/chokepoints.json schema so choke-point enforcement cannot fail open.");
      return [];
    }
    const valid: ChokePointRule[] = [];
    for (const raw of parsed.rules) {
      if (!isRecord(raw) || typeof raw.pattern !== "string" || !raw.pattern.trim() || typeof raw.replacement !== "string") {
        push(findings, cfg.rel, 1, "chokepoints-invalid-json", "R0", "error", `${cfg.rel} contains a malformed or null choke-point rule entry.`, "Give every choke-point rule a non-empty 'pattern' and 'replacement'.");
        continue;
      }
      if (Array.isArray(raw.allowPaths) && raw.allowPaths.some((p) => typeof p !== "string" || p.trim().replace(/^\/+/, "") === "" || p.trim() === "*" || p.trim() === "**")) {
        push(findings, cfg.rel, 1, "chokepoints-invalid-json", "R0", "error", `${cfg.rel} rule '${raw.pattern}' has an empty or universal allowPaths entry.`, "Scope allowPaths to the exact choke-point wrapper file.");
        continue;
      }
      valid.push({
        pattern: raw.pattern,
        replacement: raw.replacement,
        ...(Array.isArray(raw.languages) ? { languages: raw.languages.filter((x): x is string => typeof x === "string") } : {}),
        ...(Array.isArray(raw.allowPaths) ? { allowPaths: raw.allowPaths.filter((x): x is string => typeof x === "string") } : {}),
        ...(typeof raw.reason === "string" ? { reason: raw.reason } : {}),
      });
    }
    return valid;
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

  const compiled = rules.map((r) => ({
    rule: r,
    allowSet: (r.allowPaths ?? []).map((p) => p.replace(/^\/+/, "")),
    langSet: r.languages ? new Set(r.languages) : null,
  }));

  for (const file of repo.files) {
    if (!file.language || file.isTest) continue;
    const masked = maskCode(file.content, file.language, true);
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

function findLineForNeedle(lines: readonly string[], needle: string): number {
  for (let i = 0; i < lines.length; i++) {
    if ((lines[i] ?? "").includes(needle)) return i + 1;
  }
  return 1;
}

function auditUsesRef(file: ScannedFile, lines: readonly string[], usesVal: string, findings: Finding[]): void {
  const trimmed = usesVal.trim();
  if (trimmed.startsWith("./") || trimmed.startsWith("../")) return;
  const line = findLineForNeedle(lines, trimmed);
  if (trimmed.startsWith("docker://")) {
    const img = trimmed.slice(9);
    if (!/@sha256:[0-9a-f]{64}$/i.test(img)) {
      push(findings, file.rel, line, "ci-unpinned-third-party-action", "R0", "warn", `Docker action '${trimmed}' is not pinned to an immutable @sha256 digest.`, "Pin docker:// actions with '@sha256:<64-hex-digest>'.");
    }
    return;
  }
  const atIdx = trimmed.lastIndexOf("@");
  if (atIdx <= 0) return;
  const action = trimmed.slice(0, atIdx);
  const ref = trimmed.slice(atIdx + 1);
  if (HEX_40.test(ref) || /^(?:actions|github)\//i.test(action)) return;
  push(
    findings, file.rel, line, "ci-unpinned-third-party-action", "R0", "warn",
    `Third-party GitHub Action '${action}@${ref}' is not pinned to a full 40-char commit SHA.`,
    `Pin '${action}@<40-char-commit-sha> # ${ref}' to prevent supply-chain tag hijacking.`,
  );
}

function auditContainerImage(file: ScannedFile, lines: readonly string[], img: unknown, findings: Finding[]): void {
  const image = typeof img === "string" ? img : isRecord(img) && typeof img.image === "string" ? img.image : undefined;
  if (!image) return;
  if (/:latest$/i.test(image) || (!image.includes(":") && !image.includes("@sha256:"))) {
    push(findings, file.rel, findLineForNeedle(lines, image), "ci-unpinned-third-party-action", "R0", "warn", `Workflow container/service image '${image}' uses a mutable tag instead of a pinned version or @sha256 digest.`, "Pin container images to an immutable @sha256 digest.");
  }
}

function auditWorkflowImmuneSupplyChain(file: ScannedFile, findings: Finding[]): void {
  const lines = file.content.split(/\r?\n/);

  if (file.rel.startsWith(".github/workflows/") && !/^\s*permissions:/m.test(file.content)) {
    push(findings, file.rel, 1, "ci-missing-explicit-permissions", "R0", "warn", "GitHub Actions workflow omits top-level 'permissions:' block.", "Add top-level 'permissions: { contents: read }' and grant narrower write scopes only on release jobs.");
  }

  for (let i = 0; i < lines.length; i++) {
    const raw = lines[i] ?? "";
    if (!/^\s*#/.test(raw) && FETCH_TO_SHELL.test(raw)) {
      push(findings, file.rel, i + 1, "ci-curl-pipe-shell", "R0", "error", "Workflow pipes remote download directly into a shell/script interpreter.", "Download a pinned checksum-verified release artifact or use a SHA-pinned action.");
    }
  }

  try {
    const doc: unknown = YAML.parse(file.content);
    if (isRecord(doc) && isRecord(doc.jobs)) {
      for (const job of Object.values(doc.jobs)) {
        if (!isRecord(job)) continue;
        if (typeof job.uses === "string") auditUsesRef(file, lines, job.uses, findings);
        if (job.container) auditContainerImage(file, lines, job.container, findings);
        if (isRecord(job.services)) {
          for (const svc of Object.values(job.services)) auditContainerImage(file, lines, svc, findings);
        }
        if (Array.isArray(job.steps)) {
          for (const step of job.steps) {
            if (!isRecord(step)) continue;
            if (typeof step.uses === "string") auditUsesRef(file, lines, step.uses, findings);
          }
        }
      }
    }
  } catch {
    void 0;
  }

  const hasDeployOrWrite = /\b(?:id-token:\s*write|packages:\s*write|deployments:\s*write|vercel\s+deploy|npm\s+publish|docker\s+push|aws-actions\/configure-aws-credentials)\b/i.test(file.content);
  if (hasDeployOrWrite && /uses:\s*["']?actions\/checkout@/i.test(file.content) && !/persist-credentials:\s*false/i.test(file.content)) {
    push(findings, file.rel, 1, "ci-checkout-missing-persist-creds-false", "R0", "warn", "Workflow with privileged deploy/OIDC steps uses actions/checkout without 'persist-credentials: false'.", "Pass 'with: { persist-credentials: false }' to actions/checkout so GITHUB_TOKEN is not left in .git/config.");
  }
}

function auditLinterImmuneConfigs(file: ScannedFile, findings: Finding[]): void {
  const base = file.rel.split("/").pop()?.toLowerCase() ?? "";
  if (base === "directory.build.props" && !file.rel.startsWith("templates/")) {
    const hasAnalyzers = /<EnableNETAnalyzers>\s*true\s*<\/EnableNETAnalyzers>/i.test(file.content) || /<AnalysisLevel>\s*latest/i.test(file.content);
    const hasTreatWarn = /<TreatWarningsAsErrors>\s*true\s*<\/TreatWarningsAsErrors>/i.test(file.content);
    if (!hasAnalyzers || !hasTreatWarn) {
      push(findings, file.rel, 1, "immune-dotnet-missing-analyzers", "R1", "warn", "Directory.Build.props is missing <EnableNETAnalyzers>true</EnableNETAnalyzers> or <TreatWarningsAsErrors>true</TreatWarningsAsErrors>.", "Enable built-in .NET analyzers at AnalysisLevel=latest and enforce TreatWarningsAsErrors=true.");
    }
  }
  if (base === ".golangci.yml" || base === ".golangci.yaml") {
    const missing = ["errcheck", "bodyclose", "gosec"].filter((r) => findTokenOffsets(file.content, r).length === 0);
    if (missing.length > 0) {
      push(findings, file.rel, 1, "immune-go-missing-safety-linters", "R1", "warn", `.golangci.yml is missing critical Go safety linters: ${missing.join(", ")}.`, `Enable ${missing.join(", ")} in .golangci.yml.`);
    }
  }
}

export function analyzeImmuneSystemGates(repo: DiscoveredRepo): Finding[] {
  const findings: Finding[] = [];
  auditChokePoints(repo, findings);
  for (const file of repo.files) {
    if (file.isWorkflow) auditWorkflowImmuneSupplyChain(file, findings);
    else auditLinterImmuneConfigs(file, findings);
  }
  return findings;
}
