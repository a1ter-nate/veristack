import YAML from "yaml";
import type { DiscoveredRepo, ScannedFile } from "@veristack/plugin";
import { lineOf, maskCode } from "@veristack/plugin";
import type { Finding } from "@veristack/plugin";

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

interface ImmuneFindingSpec {
  file: string;
  line: number;
  rule: string;
  rung: Finding["rung"];
  severity: Finding["severity"];
  message: string;
  fix: string;
}

function push(findings: Finding[], spec: ImmuneFindingSpec): void {
  findings.push({ id: `IMM:${spec.rule}:${spec.file}:${spec.line}`, category: "ci-hygiene", ...spec });
}

function loadChokePoints(repo: DiscoveredRepo, findings: Finding[]): ChokePointRule[] {
  const cfg = repo.files.find((f) => /(?:^|\/)\.verification\/chokepoints\.json$/i.test(f.rel));
  if (!cfg) return [];
  try {
    const parsed = JSON.parse(cfg.content) as { rules?: unknown };
    if (!isRecord(parsed) || !Array.isArray(parsed.rules) || parsed.rules.length === 0) {
      push(findings, { file: cfg.rel, line: 1, rule: "chokepoints-invalid-json", rung: "R0", severity: "error", message: `${cfg.rel} must contain a non-empty 'rules' array.`, fix: "Fix .verification/chokepoints.json schema so choke-point enforcement cannot fail open." });
      return [];
    }
    const valid: ChokePointRule[] = [];
    for (const raw of parsed.rules) {
      if (!isRecord(raw) || typeof raw.pattern !== "string" || !raw.pattern.trim() || typeof raw.replacement !== "string") {
        push(findings, { file: cfg.rel, line: 1, rule: "chokepoints-invalid-json", rung: "R0", severity: "error", message: `${cfg.rel} contains a malformed or null choke-point rule entry.`, fix: "Give every choke-point rule a non-empty 'pattern' and 'replacement'." });
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
        push(findings, { file: cfg.rel, line: 1, rule: "chokepoints-invalid-json", rung: "R0", severity: "error", message: `${cfg.rel} rule '${raw.pattern}' has an overly broad or invalid allowPaths entry (must be an exact file path).`, fix: "Scope allowPaths to exact choke-point wrapper file paths (e.g. 'src/db/client.ts')." });
        continue;
      }
      if (raw.languages !== undefined) {
        if (!Array.isArray(raw.languages) || raw.languages.length === 0 || raw.languages.some((l) => typeof l !== "string" || !VALID_CHOKE_LANGS.has(l))) {
          push(findings, { file: cfg.rel, line: 1, rule: "chokepoints-invalid-json", rung: "R0", severity: "error", message: `${cfg.rel} rule '${raw.pattern}' has empty or unrecognized languages (expected lowercase: typescript, javascript, csharp, python, rust, go).`, fix: "List valid lowercase language identifiers or omit 'languages' to apply to all." });
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
    push(findings, { file: cfg.rel, line: 1, rule: "chokepoints-invalid-json", rung: "R0", severity: "error", message: `${cfg.rel} contains invalid JSON — failing closed.`, fix: "Fix JSON syntax in .verification/chokepoints.json." });
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
        push(findings, {
          file: file.rel, line: lineOf(file.content, offset), rule: "chokepoint-banned-primitive", rung: "R0", severity: "error",
          message: `Direct use of banned primitive '${c.rule.pattern}' bypasses the repo choke point (${c.rule.reason ?? "enforced via .verification/chokepoints.json"}).`,
          fix: `Use '${c.rule.replacement}' instead of '${c.rule.pattern}'.`,
        });
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
    if (!/@sha256:[0-9a-f]{64}$/i.test(trimmed.slice(9))) {
      push(findings, { file: file.rel, line, rule: "ci-unpinned-third-party-action", rung: "R0", severity: "warn", message: `Docker action '${trimmed}' is not pinned to an immutable @sha256 digest.`, fix: "Pin docker:// actions with '@sha256:<64-hex-digest>'." });
    }
    return;
  }
  const atIdx = trimmed.lastIndexOf("@");
  if (atIdx <= 0) return;
  const action = trimmed.slice(0, atIdx);
  const ref = trimmed.slice(atIdx + 1);
  if (HEX_40.test(ref) || /^(?:actions|github)\//i.test(action)) return;
  push(findings, {
    file: file.rel, line, rule: "ci-unpinned-third-party-action", rung: "R0", severity: "warn",
    message: `Third-party GitHub Action '${action}@${ref}' is not pinned to a full 40-char commit SHA.`,
    fix: `Pin '${action}@<40-char-commit-sha> # ${ref}' to prevent supply-chain tag hijacking.`,
  });
}

function auditContainerImage(file: ScannedFile, lines: readonly string[], img: unknown, findings: Finding[]): void {
  const image = typeof img === "string" ? img : isRecord(img) && typeof img.image === "string" ? img.image : undefined;
  if (!image) return;
  if (/:latest$/i.test(image) || (!image.includes(":") && !image.includes("@sha256:"))) {
    push(findings, { file: file.rel, line: findLineForNeedle(lines, image), rule: "ci-unpinned-third-party-action", rung: "R0", severity: "warn", message: `Workflow container/service image '${image}' uses a mutable tag instead of a pinned version or @sha256 digest.`, fix: "Pin container images to an immutable @sha256 digest." });
  }
}

function firstNonFlagTok(toks: readonly string[]): string | undefined {
  for (let i = 1; i < toks.length; i++) {
    const t = toks[i];
    if (t && !t.startsWith("-")) return t;
  }
  return undefined;
}

interface DownloadState {
  downloadedFiles: Set<string>;
  verifiedFiles: Set<string>;
  globalChecksumVerified: boolean;
}

function checkDownloadedExecStmt(
  file: ScannedFile,
  lines: readonly string[],
  st: string,
  state: DownloadState,
): Finding[] {
  const out: Finding[] = [];
  if (state.downloadedFiles.size === 0) return out;
  const toks = st.split(/\s+/).map((t) => t.replace(/^["']|["']$/g, ""));
  const cmdHead = (toks[0] ?? "").replace(/^(?:\/[\w.-]+)*\//, "");
  const isExecInterp = /^(?:sh|bash|zsh|dash|node|bun|python3?|perl|ruby|source|\.)$/.test(cmdHead);
  const firstNonFlagArg = firstNonFlagTok(toks);
  const isChmodExec = cmdHead === "chmod" && /\+x|755|700/.test(st);
  for (const f of state.downloadedFiles) {
    if (state.verifiedFiles.has(f) || state.globalChecksumVerified) continue;
    if (!st.includes(f) || /^(?:curl|wget|rm|echo|printf)$/.test(cmdHead)) continue;
    const directExec = toks[0] === `./${f}` || toks[0] === f;
    const chmodExec = isChmodExec && toks.includes(f);
    const interpExec = isExecInterp && (firstNonFlagArg === f || firstNonFlagArg === `./${f}`);
    if (directExec || chmodExec || interpExec) {
      push(out, { file: file.rel, line: findLineForNeedle(lines, f), rule: "ci-curl-pipe-shell", rung: "R0", severity: "error", message: `Script downloads and executes '${f}' without prior verified checksum ('sha256sum -c' / 'gpg --verify').`, fix: "Verify sha256sum -c against a pinned digest before executing downloaded scripts." });
    }
  }
  return out;
}

function auditRunScriptSupplyChain(file: ScannedFile, lines: readonly string[], runScript: string, findings: Finding[]): void {
  if (!runScript) return;
  const joinedLines: string[] = [];
  let buf = "";
  for (const rawLine of runScript.split(/\r?\n/)) {
    const trimmedEnd = rawLine.replace(/\s+$/, "");
    if (trimmedEnd.endsWith("\\")) buf += `${trimmedEnd.slice(0, -1)} `;
    else { joinedLines.push(buf + rawLine); buf = ""; }
  }
  if (buf) joinedLines.push(buf);
  const state: DownloadState = { downloadedFiles: new Set(), verifiedFiles: new Set(), globalChecksumVerified: false };
  const CHECKSUM_CMD = /(?:^|\|\s*)(?:sudo\s+)?(?:sha256sum\s+(?:-[A-Za-z]*c|--check)|shasum\s+-a\s+256\s+(?:-[A-Za-z]*c|--check)|sha512sum\s+(?:-[A-Za-z]*c|--check)|gpg\s+--verify)\b/i;
  for (const line of joinedLines) {
    if (/^\s*#/.test(line)) continue;
    if (FETCH_TO_SHELL.test(line)) {
      push(findings, { file: file.rel, line: findLineForNeedle(lines, line.trim().slice(0, 32)), rule: "ci-curl-pipe-shell", rung: "R0", severity: "error", message: "Script pipes or evals remote download directly into a shell/script interpreter.", fix: "Download a pinned checksum-verified release artifact or use a SHA-pinned action." });
      continue;
    }
    for (const stmt of line.split(/\s*(?:&&|;)\s*/)) {
      const st = stmt.trim();
      if (!st || st.startsWith("#")) continue;
      if (CHECKSUM_CMD.test(st) && !/\|\|\s*(?:true|:)\b/.test(st)) {
        state.globalChecksumVerified = true;
        for (const f of state.downloadedFiles) state.verifiedFiles.add(f);
        continue;
      }
      const dl = DOWNLOAD_TO_FILE.exec(st);
      const dlTarget = (dl?.[1] ?? dl?.[2] ?? dl?.[3] ?? "").replace(/^["']|["']$/g, "");
      if (dlTarget && dlTarget !== "/dev/null") {
        state.downloadedFiles.add(dlTarget);
        state.verifiedFiles.delete(dlTarget);
        continue;
      }
      findings.push(...checkDownloadedExecStmt(file, lines, st, state));
    }
  }
}

function auditWorkflowStepsList(file: ScannedFile, lines: readonly string[], steps: readonly unknown[], findings: Finding[]): void {
  for (const step of steps) {
    if (!isRecord(step)) continue;
    if (typeof step.uses === "string") auditUsesRef(file, lines, step.uses, findings);
    if (typeof step.run === "string") auditRunScriptSupplyChain(file, lines, step.run, findings);
  }
}

function auditWorkflowParsedDoc(file: ScannedFile, lines: readonly string[], doc: Record<string, unknown>, findings: Finding[]): boolean {
  let parsedSteps = false;
  if (isRecord(doc.runs) && Array.isArray(doc.runs.steps)) {
    parsedSteps = true;
    auditWorkflowStepsList(file, lines, doc.runs.steps, findings);
  }
  if (!isRecord(doc.jobs)) return parsedSteps;
  parsedSteps = true;
  for (const job of Object.values(doc.jobs)) {
    if (!isRecord(job)) continue;
    if (typeof job.uses === "string") auditUsesRef(file, lines, job.uses, findings);
    if (job.container) auditContainerImage(file, lines, job.container, findings);
    if (isRecord(job.services)) for (const svc of Object.values(job.services)) auditContainerImage(file, lines, svc, findings);
    if (Array.isArray(job.steps)) auditWorkflowStepsList(file, lines, job.steps, findings);
  }
  return parsedSteps;
}

function auditWorkflowImmuneSupplyChain(file: ScannedFile, findings: Finding[]): void {
  if (!file.content) return;
  const lines = file.content.split(/\r?\n/);
  if (file.rel.startsWith(".github/workflows/") && !/^\s*permissions:/m.test(file.content)) {
    push(findings, { file: file.rel, line: 1, rule: "ci-missing-explicit-permissions", rung: "R0", severity: "warn", message: "GitHub Actions workflow omits top-level 'permissions:' block.", fix: "Add top-level 'permissions: { contents: read }' and grant narrower write scopes only on release jobs." });
  }
  let parsedSteps = false;
  try {
    const doc: unknown = YAML.parse(file.content);
    if (isRecord(doc)) parsedSteps = auditWorkflowParsedDoc(file, lines, doc, findings);
  } catch { void 0; }
  if (!parsedSteps) auditRunScriptSupplyChain(file, lines, file.content, findings);
  const hasDeployOrWrite = /\b(?:id-token:\s*write|packages:\s*write|deployments:\s*write|vercel\s+deploy|npm\s+publish|docker\s+push|aws-actions\/configure-aws-credentials)\b/i.test(file.content);
  if (hasDeployOrWrite && /uses:\s*["']?actions\/checkout@/i.test(file.content) && !/persist-credentials:\s*false/i.test(file.content)) {
    push(findings, { file: file.rel, line: 1, rule: "ci-checkout-missing-persist-creds-false", rung: "R0", severity: "warn", message: "Workflow with privileged deploy/OIDC steps uses actions/checkout without 'persist-credentials: false'.", fix: "Pass 'with: { persist-credentials: false }' to actions/checkout so GITHUB_TOKEN is not left in .git/config." });
  }
}

function auditLinterImmuneConfigs(file: ScannedFile, findings: Finding[]): void {
  const base = file.rel.split("/").pop()?.toLowerCase() ?? "";
  if (base === "directory.build.props" && !file.rel.startsWith("templates/")) {
    const hasAnalyzers = /<EnableNETAnalyzers>\s*true\s*<\/EnableNETAnalyzers>/i.test(file.content) || /<AnalysisLevel>\s*latest/i.test(file.content);
    const hasTreatWarn = /<TreatWarningsAsErrors>\s*true\s*<\/TreatWarningsAsErrors>/i.test(file.content);
    if (!hasAnalyzers || !hasTreatWarn) {
      push(findings, { file: file.rel, line: 1, rule: "immune-dotnet-missing-analyzers", rung: "R1", severity: "warn", message: "Directory.Build.props is missing <EnableNETAnalyzers>true</EnableNETAnalyzers> or <TreatWarningsAsErrors>true</TreatWarningsAsErrors>.", fix: "Enable built-in .NET analyzers at AnalysisLevel=latest and enforce TreatWarningsAsErrors=true." });
    }
  }
  if (base === ".golangci.yml" || base === ".golangci.yaml") {
    const missing = ["errcheck", "bodyclose", "gosec"].filter((r) => findTokenOffsets(file.content, r).length === 0);
    if (missing.length > 0) {
      push(findings, { file: file.rel, line: 1, rule: "immune-go-missing-safety-linters", rung: "R1", severity: "warn", message: `.golangci.yml is missing critical Go safety linters: ${missing.join(", ")}.`, fix: `Enable ${missing.join(", ")} in .golangci.yml.` });
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
