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
const VALID_CHOKE_LANGS = new Set(["typescript", "javascript", "csharp", "python", "rust", "go"]);
const FETCH_TO_SHELL =
  /\b(?:curl|wget)\b[^\n|]*\|\s*(?:sudo\s+(?:-[A-Za-z]+\s+)*)?(?:env\s+)?(?:(?:\/[\w.-]+)*\/)?(?:sh|bash|zsh|dash|ksh|node|python3?|perl|ruby|tee\b[^\n]*\|\s*(?:(?:\/[\w.-]+)*\/)?(?:sh|bash))|\b(?:bash|sh|zsh|source|\.)\s+<\(\s*(?:curl|wget)\b|\b(?:sh|bash|eval)\s+(?:-c\s+)?["']?\$\(\s*(?:curl|wget)\b/i;
const DOWNLOAD_TO_FILE =
  /\b(?:curl\b[^\n]*(?:-[A-Za-z]*o|--output)(?:=|\s+)([^\s;|&]+)|wget\b[^\n]*(?:-[A-Za-z]*O|--output-document)(?:=|\s+)([^\s;|&]+)|(?:curl|wget)\b[^\n]*>\s*([^\s;|&]+))/i;

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
      if (
        Array.isArray(raw.allowPaths) &&
        raw.allowPaths.some((p) => {
          if (typeof p !== "string") return true;
          const clean = p.trim().replace(/^\/+/, "").replace(/\/+$/, "");
          const hasExt = /\.[A-Za-z0-9]{1,8}$/.test(clean);
          return clean === "" || clean.includes("*") || !hasExt;
        })
      ) {
        push(findings, cfg.rel, 1, "chokepoints-invalid-json", "R0", "error", `${cfg.rel} rule '${raw.pattern}' has an overly broad or invalid allowPaths entry (must be an exact file path).`, "Scope allowPaths to exact choke-point wrapper file paths (e.g. 'src/db/client.ts').");
        continue;
      }
      if (raw.languages !== undefined) {
        if (!Array.isArray(raw.languages) || raw.languages.length === 0 || raw.languages.some((l) => typeof l !== "string" || !VALID_CHOKE_LANGS.has(l))) {
          push(findings, cfg.rel, 1, "chokepoints-invalid-json", "R0", "error", `${cfg.rel} rule '${raw.pattern}' has empty or unrecognized languages (expected lowercase: typescript, javascript, csharp, python, rust, go).`, "List valid lowercase language identifiers or omit 'languages' to apply to all.");
          continue;
        }
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
      if (c.allowSet.some((allowed) => file.rel === allowed)) continue;
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

function firstNonFlagTok(toks: readonly string[]): string | undefined {
  for (let i = 1; i < toks.length; i++) {
    const t = toks[i];
    if (t && !t.startsWith("-")) return t;
  }
  return undefined;
}

function auditRunScriptSupplyChain(file: ScannedFile, lines: readonly string[], runScript: string, findings: Finding[]): void {
  const joinedLines: string[] = [];
  let buf = "";
  for (const rawLine of runScript.split(/\r?\n/)) {
    const trimmedEnd = rawLine.replace(/\s+$/, "");
    if (trimmedEnd.endsWith("\\")) buf += `${trimmedEnd.slice(0, -1)} `;
    else { joinedLines.push(buf + rawLine); buf = ""; }
  }
  if (buf) joinedLines.push(buf);
  const downloadedFiles = new Set<string>();
  const verifiedFiles = new Set<string>();
  let globalChecksumVerified = false;
  const CHECKSUM_CMD = /(?:^|\|\s*)(?:sudo\s+)?(?:sha256sum\s+(?:-[A-Za-z]*c|--check)|shasum\s+-a\s+256\s+(?:-[A-Za-z]*c|--check)|sha512sum\s+(?:-[A-Za-z]*c|--check)|gpg\s+--verify)\b/i;
  for (const line of joinedLines) {
    if (/^\s*#/.test(line)) continue;
    if (FETCH_TO_SHELL.test(line)) {
      push(findings, file.rel, findLineForNeedle(lines, line.trim().slice(0, 32)), "ci-curl-pipe-shell", "R0", "error", "Script pipes or evals remote download directly into a shell/script interpreter.", "Download a pinned checksum-verified release artifact or use a SHA-pinned action.");
      continue;
    }
    const stmts = line.split(/\s*(?:&&|;)\s*/);
    for (const stmt of stmts) {
      const st = stmt.trim();
      if (!st || st.startsWith("#")) continue;
      if (CHECKSUM_CMD.test(st) && !/\|\|\s*(?:true|:)\b/.test(st)) {
        globalChecksumVerified = true;
        for (const f of downloadedFiles) verifiedFiles.add(f);
        continue;
      }
      const dl = DOWNLOAD_TO_FILE.exec(st);
      const dlTarget = (dl?.[1] ?? dl?.[2] ?? dl?.[3] ?? "").replace(/^["']|["']$/g, "");
      if (dlTarget && dlTarget !== "/dev/null") {
        downloadedFiles.add(dlTarget);
        verifiedFiles.delete(dlTarget);
        continue;
      }
      if (downloadedFiles.size > 0) {
        const toks = st.split(/\s+/).map((t) => t.replace(/^["']|["']$/g, ""));
        const cmdHead = (toks[0] ?? "").replace(/^(?:\/[\w.-]+)*\//, "");
        const isExecInterp = /^(?:sh|bash|zsh|dash|node|bun|python3?|perl|ruby|source|\.)$/.test(cmdHead);
        const firstNonFlagArg = firstNonFlagTok(toks);
        const isChmodExec = cmdHead === "chmod" && /\+x|755|700/.test(st);
        for (const f of downloadedFiles) {
          if (verifiedFiles.has(f) || globalChecksumVerified) continue;
          if (!st.includes(f) || /^(?:curl|wget|rm|echo|printf)$/.test(cmdHead)) continue;
          const directExec = toks[0] === `./${f}` || toks[0] === f;
          const chmodExec = isChmodExec && toks.includes(f);
          const interpExec = isExecInterp && (firstNonFlagArg === f || firstNonFlagArg === `./${f}`);
          if (directExec || chmodExec || interpExec) {
            push(findings, file.rel, findLineForNeedle(lines, f), "ci-curl-pipe-shell", "R0", "error", `Script downloads and executes '${f}' without prior verified checksum ('sha256sum -c' / 'gpg --verify').`, "Verify sha256sum -c against a pinned digest before executing downloaded scripts.");
          }
        }
      }
    }
  }
}

function auditWorkflowImmuneSupplyChain(file: ScannedFile, findings: Finding[]): void {
  const lines = file.content.split(/\r?\n/);

  if (file.rel.startsWith(".github/workflows/") && !/^\s*permissions:/m.test(file.content)) {
    push(findings, file.rel, 1, "ci-missing-explicit-permissions", "R0", "warn", "GitHub Actions workflow omits top-level 'permissions:' block.", "Add top-level 'permissions: { contents: read }' and grant narrower write scopes only on release jobs.");
  }

  let parsedSteps = false;
  try {
    const doc: unknown = YAML.parse(file.content);
    if (isRecord(doc)) {
      if (isRecord(doc.runs) && Array.isArray(doc.runs.steps)) {
        parsedSteps = true;
        for (const step of doc.runs.steps) {
          if (!isRecord(step)) continue;
          if (typeof step.uses === "string") auditUsesRef(file, lines, step.uses, findings);
          if (typeof step.run === "string") auditRunScriptSupplyChain(file, lines, step.run, findings);
        }
      }
      if (isRecord(doc.jobs)) {
        parsedSteps = true;
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
              if (typeof step.run === "string") auditRunScriptSupplyChain(file, lines, step.run, findings);
            }
          }
        }
      }
    }
  } catch {
    void 0;
  }

  if (!parsedSteps) {
    auditRunScriptSupplyChain(file, lines, file.content, findings);
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
    if (file.isWorkflow || /(?:^|\/)\.github\/(?:.+\/)?action\.ya?ml$/i.test(file.rel)) {
      auditWorkflowImmuneSupplyChain(file, findings);
    } else if (/\.(?:sh|bash)$/i.test(file.rel)) {
      auditRunScriptSupplyChain(file, file.content.split(/\r?\n/), file.content, findings);
    } else {
      auditLinterImmuneConfigs(file, findings);
    }
  }
  return findings;
}
