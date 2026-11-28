import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { scanSingleFile } from "./check-file.ts";

export type ReportKind = "fp" | "fn" | "crash" | "bug";
export interface GhRunResult { status: number | null; stdout: string; stderr: string; error?: Error; }
export type GhRunner = (args: readonly string[], timeoutMs: number) => GhRunResult;

export interface ToolReportOptions {
  repoRoot?: string;
  rule?: string;
  file?: string;
  kind?: ReportKind;
  reason?: string;
  command?: string;
  anonymize?: boolean;
  noRerun?: boolean;
}

export interface ToolReportEntry {
  schemaVersion: 1;
  timestamp: string;
  toolVersion: string;
  runtime: string;
  os: string;
  kind: ReportKind;
  rule: string;
  file: string | null;
  line: number | null;
  language: string | null;
  reason: string;
  command: string | null;
  finding: string | null;
  snippet: string | null;
  anonymized: boolean;
}

export interface ToolReportPayload { entry: ToolReportEntry; title: string; label: "false-positive" | "bug"; markdown: string; }
export interface FlushQueueOptions { repoRoot?: string; clear?: boolean; }
export interface FlushQueueGroup { key: string; kind: ReportKind; rule: string; count: number; entries: ToolReportEntry[]; }
export interface FlushQueueResult {
  queuePath: string;
  rawCount: number;
  uniqueCount: number;
  groups: FlushQueueGroup[];
  title: string;
  label: "false-positive" | "bug";
  markdown: string;
  cleared: boolean;
}

const TARGET_REPO = "a1ter-nate/veristack";
const FEEDBACK_QUEUE_REL = ".verification/tool-feedback.jsonl";
const MAX_GITHUB_URL_LEN = 7500;
const TRUNCATION_NOTE = "\n\n_(Truncated to fit GitHub URL length limit. Run `vstack report --out report.md` for the full report.)_";

const PRESERVED_KEYWORDS = new Set([
  "abstract", "and", "any", "as", "async", "await", "bool", "boolean", "break", "case", "catch", "class",
  "const", "continue", "crate", "def", "default", "delete", "do", "elif", "else", "enum", "export", "extends",
  "extern", "false", "False", "finally", "fn", "for", "from", "func", "function", "go", "if", "impl", "import",
  "in", "instanceof", "int", "interface", "internal", "is", "let", "loop", "match", "mod", "mut", "namespace",
  "new", "nil", "None", "not", "null", "number", "object", "of", "or", "override", "package", "pass", "private",
  "protected", "pub", "public", "raise", "readonly", "record", "ref", "return", "self", "Self", "static",
  "string", "struct", "super", "switch", "this", "throw", "trait", "true", "True", "try", "type", "typeof",
  "undefined", "unsafe", "use", "using", "var", "virtual", "void", "where", "while", "with", "yield",
  "Array", "BigInt", "Buffer", "Console", "Date", "Error", "JSON", "Map", "Math", "Number", "Object", "Option",
  "Promise", "RegExp", "Result", "Set", "String", "Task", "URL", "Vec", "console", "process", "window", "document",
]);

function resolveVeristackVersion(): string {
  const here = path.dirname(fileURLToPath(import.meta.url));
  for (const rel of ["../package.json", "../../package.json", "../../../package.json", "../../../../package.json"]) {
    const candidate = path.resolve(here, rel);
    if (!fs.existsSync(candidate)) continue;
    try {
      const doc = JSON.parse(fs.readFileSync(candidate, "utf8")) as { name?: string; version?: string };
      if (doc.name === "veristack" && typeof doc.version === "string") return doc.version;
    } catch { continue; }
  }
  return "0.1.27";
}

function runtimeString(): string {
  const bunVer = (process.versions as Record<string, string | undefined>).bun;
  return bunVer ? `bun ${bunVer}` : `node ${process.version}`;
}

function parseFileAndLine(rawFile: string | undefined): { filePath: string | null; line: number | null } {
  if (!rawFile || !rawFile.trim()) return { filePath: null, line: null };
  const trimmed = rawFile.trim();
  const match = /^(.+):(\d+)$/.exec(trimmed);
  if (match?.[1] && match[2]) {
    const num = Number(match[2]);
    if (Number.isInteger(num) && num >= 1) return { filePath: match[1], line: num };
  }
  return { filePath: trimmed, line: null };
}

function inferLanguage(filePath: string | null): string | null {
  if (!filePath) return null;
  const low = filePath.toLowerCase();
  if (/\.[cm]?tsx?$/.test(low)) return "typescript";
  if (/\.[cm]?jsx?$/.test(low)) return "javascript";
  if (low.endsWith(".cs")) return "csharp";
  if (low.endsWith(".rs")) return "rust";
  if (low.endsWith(".py")) return "python";
  if (low.endsWith(".go")) return "go";
  if (low.endsWith(".sql")) return "sql";
  if (/\.(?:sh|bash)$/.test(low)) return "shell";
  if (/\.ya?ml$/.test(low)) return "yaml";
  return null;
}

export function redactReportText(text: string, repoRoot?: string): string {
  if (!text) return "";
  let out = text;
  if (repoRoot) {
    const absRoot = path.resolve(repoRoot);
    for (const variant of new Set([absRoot, absRoot.split(path.sep).join("/")])) {
      if (variant.length > 1) out = out.replaceAll(variant, "<repo>");
    }
  }
  const home = os.homedir();
  if (home && home.length > 1) {
    for (const variant of new Set([home, home.split(path.sep).join("/")])) {
      out = out.replaceAll(variant, "<home>");
    }
  }
  return out
    .replace(/(?:\/Users|\/home)\/[^/\s"'`]+/g, "<home>")
    .replace(/[A-Za-z]:\\Users\\[^\\\s"'`]+/g, "<home>")
    .replace(/-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----/g, "<redacted-private-key>")
    .replace(/\b((?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|rediss|amqps?|https?):\/\/)([^:\s/@]+):([^@\s/]+)@/gi, "$1<redacted>:<redacted>@")
    .replace(/\b(Bearer\s+)[A-Za-z0-9._~+/=-]{12,}/gi, "$1<redacted-token>")
    .replace(/\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g, "<redacted-jwt>")
    .replace(/\b(?:gh[pousr]_[A-Za-z0-9]{16,}|github_pat_[A-Za-z0-9_]{20,}|sk_(?:live|test)_[A-Za-z0-9]{12,}|pk_(?:live|test)_[A-Za-z0-9]{12,}|sk-[A-Za-z0-9_-]{16,}|AKIA[0-9A-Z]{16}|xox[baprs]-[A-Za-z0-9-]{12,}|npm_[A-Za-z0-9]{16,}|AIza[0-9A-Za-z_-]{20,})\b/g, "<redacted-secret>")
    .replace(/\b([A-Z0-9_]*(?:API_KEY|SECRET|TOKEN|PASSWORD|PASSWD|PRIVATE_KEY|ACCESS_KEY))\s*([:=])\s*(?:"[^"\n]*"|'[^'\n]*'|`[^`\n]*`|[^\s,;]+)/gi, "$1$2<redacted>")
    .replace(/\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g, "<redacted-email>");
}

function anonymizeCodeLine(line: string, idMap: Map<string, string>, fnMap: Map<string, string>): string {
  const noStrings = line
    .replace(/"(?:\\.|[^"\\\n])*"/g, '"<str>"')
    .replace(/'(?:\\.|[^'\\\n])*'/g, '"<str>"')
    .replace(/`(?:\\.|[^`\\\n])*`/g, '"<str>"');
  return noStrings.replace(/\b([A-Za-z_$][A-Za-z0-9_$]*)\b(\s*\()?|\b(0x[0-9a-fA-F]+|\d{5,})\b/g, (full, ident: string | undefined, openParen: string | undefined, bigNum: string | undefined) => {
    if (bigNum) return "0";
    if (!ident || PRESERVED_KEYWORDS.has(ident) || ident === "str") return full;
    if (openParen) {
      let alias = fnMap.get(ident);
      if (!alias) { alias = `fn${fnMap.size + 1}`; fnMap.set(ident, alias); }
      return `${alias}${openParen}`;
    }
    let alias = idMap.get(ident);
    if (!alias) { alias = `id${idMap.size + 1}`; idMap.set(ident, alias); }
    return alias;
  });
}

export function anonymizeSnippet(snippet: string): string {
  if (!snippet) return "";
  const idMap = new Map<string, string>();
  const fnMap = new Map<string, string>();
  return snippet.split(/\r?\n/).map((line) => {
    const gutter = /^([> ]\s*\d+\s*\|\s?)(.*)$/.exec(line);
    if (gutter?.[1] !== undefined) return `${gutter[1]}${anonymizeCodeLine(gutter[2] ?? "", idMap, fnMap)}`;
    return anonymizeCodeLine(line, idMap, fnMap);
  }).join("\n");
}

function extractContextSnippet(absPath: string, targetLine: number | null): string | null {
  if (!fs.existsSync(absPath) || !fs.statSync(absPath).isFile()) return null;
  const lines = fs.readFileSync(absPath, "utf8").split(/\r?\n/);
  const center = targetLine ?? 1;
  const start = Math.max(1, targetLine ? center - 8 : 1);
  const end = Math.min(lines.length, targetLine ? center + 8 : 17);
  const out: string[] = [];
  for (let i = start; i <= end; i++) out.push(`${targetLine === i ? ">" : " "} ${String(i).padStart(4, " ")} | ${lines[i - 1] ?? ""}`);
  return out.join("\n");
}

function captureSingleFileFinding(absPath: string, repoRoot: string, rule: string, targetLine: number | null): string | null {
  try {
    const res = scanSingleFile(absPath, { repoRoot, tier: "all" });
    const matched = res.findings.filter((f) => (!rule || f.rule === rule) && (!targetLine || Math.abs(f.line - targetLine) <= 2));
    const chosen = matched[0] ?? (rule ? res.findings.find((f) => f.rule === rule) : res.findings[0]);
    return chosen ? `[${chosen.severity.toUpperCase()}] ${chosen.rule} ${chosen.file}:${chosen.line} — ${chosen.message}` : null;
  } catch { return null; }
}

function formatSingleReportMarkdown(entry: ToolReportEntry): string {
  const lines = [
    "## Summary",
    `- **Kind:** \`${entry.kind}\``,
    `- **Rule:** \`${entry.rule || "n/a"}\``,
    `- **Tool:** \`veristack@${entry.toolVersion}\` (${entry.runtime}, ${entry.os})`,
    `- **Language:** \`${entry.language ?? "unknown"}\``,
    `- **Location:** \`${entry.file ? `${entry.file}${entry.line ? `:${entry.line}` : ""}` : "n/a"}\``,
  ];
  if (entry.command) lines.push(`- **Command:** \`${entry.command}\``);
  if (entry.reason) lines.push("", "## Expected vs Actual", entry.reason);
  if (entry.finding) lines.push("", "## Captured Finding", "```text", entry.finding, "```");
  if (entry.snippet) lines.push("", `## Minimal Snippet${entry.anonymized ? " (Anonymized)" : ""}`, `\`\`\`${entry.language ?? ""}`, entry.snippet, "```");
  return lines.join("\n");
}

export function buildToolReport(options: ToolReportOptions): ToolReportPayload {
  if (!options || typeof options !== "object") throw new Error("ToolReportOptions object is required.");
  const repoRoot = path.resolve(options.repoRoot ?? process.cwd());
  const kind: ReportKind = options.kind ?? "fp";
  const rule = redactReportText((options.rule ?? "").trim(), repoRoot);
  const parsedFile = parseFileAndLine(options.file);
  let relFile: string | null = null;
  let absFile: string | null = null;
  if (parsedFile.filePath) {
    absFile = path.isAbsolute(parsedFile.filePath) ? path.resolve(parsedFile.filePath) : path.resolve(repoRoot, parsedFile.filePath);
    const rel = path.relative(repoRoot, absFile).split(path.sep).join("/");
    relFile = rel.startsWith("..") ? redactReportText(absFile, repoRoot) : rel;
  }
  const language = inferLanguage(relFile);
  let snippet = absFile ? extractContextSnippet(absFile, parsedFile.line) : null;
  if (snippet) {
    snippet = redactReportText(snippet, repoRoot);
    if (options.anonymize) snippet = anonymizeSnippet(snippet);
  }
  const rawFinding = absFile && !options.noRerun ? captureSingleFileFinding(absFile, repoRoot, rule, parsedFile.line) : null;
  const finding = rawFinding ? redactReportText(rawFinding, repoRoot) : null;
  const reason = redactReportText((options.reason ?? "").trim(), repoRoot);
  const command = options.command ? redactReportText(options.command.trim(), repoRoot) : null;
  const anonFile = options.anonymize && relFile ? `<anonymized>.${language ?? "txt"}` : relFile;
  const entry: ToolReportEntry = {
    schemaVersion: 1, timestamp: new Date().toISOString(), toolVersion: resolveVeristackVersion(),
    runtime: runtimeString(), os: `${process.platform}/${process.arch}`, kind, rule: rule || "general",
    file: anonFile, line: parsedFile.line, language, reason, command,
    finding: options.anonymize && finding && relFile && anonFile ? finding.replaceAll(relFile, anonFile) : finding,
    snippet, anonymized: Boolean(options.anonymize),
  };
  const label: "false-positive" | "bug" = kind === "fp" ? "false-positive" : "bug";
  const prefix = kind === "fp" ? "[FP]" : kind === "fn" ? "[FN]" : kind === "crash" ? "[Crash]" : "[Bug]";
  const title = `${prefix} ${entry.rule}${reason ? ` — ${reason.slice(0, 72)}` : ""}`;
  return { entry, title, label, markdown: formatSingleReportMarkdown(entry) };
}

export function buildIssueUrl(input: { kind: ReportKind; title: string; body: string; repoSlug?: string; maxLength?: number }): { url: string; truncated: boolean } {
  if (!input.title) throw new Error("Issue title is required.");
  const limit = Math.max(512, input.maxLength ?? MAX_GITHUB_URL_LEN);
  const template = input.kind === "fp" ? "false-positive.yml" : "bug-report.yml";
  const label = input.kind === "fp" ? "false-positive" : "bug";
  const base = `https://github.com/${input.repoSlug ?? TARGET_REPO}/issues/new?template=${encodeURIComponent(template)}&labels=${encodeURIComponent(label)}&title=${encodeURIComponent(input.title)}&body=`;
  const full = `${base}${encodeURIComponent(input.body)}`;
  if (full.length <= limit) return { url: full, truncated: false };
  let lo = 0;
  let hi = input.body.length;
  let best = `${base}${encodeURIComponent(TRUNCATION_NOTE.trim())}`;
  while (lo <= hi) {
    const mid = Math.floor((lo + hi) / 2);
    const candidate = `${base}${encodeURIComponent(`${input.body.slice(0, mid)}${TRUNCATION_NOTE}`)}`;
    if (candidate.length <= limit) { best = candidate; lo = mid + 1; } else hi = mid - 1;
  }
  return { url: best, truncated: true };
}

function appendLocalFeedbackEntry(repoRoot: string, entry: ToolReportEntry): { queuePath: string; queuedCount: number } {
  const queuePath = path.join(repoRoot, FEEDBACK_QUEUE_REL);
  fs.mkdirSync(path.dirname(queuePath), { recursive: true });
  fs.appendFileSync(queuePath, `${JSON.stringify(entry)}\n`, "utf8");
  const lines = fs.readFileSync(queuePath, "utf8").split(/\r?\n/).filter((l) => l.trim().length > 0);
  return { queuePath: FEEDBACK_QUEUE_REL, queuedCount: lines.length };
}

function formatRollupMarkdown(groups: readonly FlushQueueGroup[], uniqueCount: number, rawCount: number): string {
  const out: string[] = [
    `# Veristack Tool Feedback Roll-up (${uniqueCount} unique / ${rawCount} queued across ${groups.length} group(s))`,
    "", "| Kind | Rule | Occurrences | Version |", "| :--- | :--- | :---: | :--- |",
  ];
  for (const g of groups) out.push(`| \`${g.kind}\` | \`${g.rule}\` | ${g.count} | \`veristack@${g.entries[0]?.toolVersion ?? "unknown"}\` |`);
  for (const g of groups) {
    out.push("", `## [${g.kind.toUpperCase()}] \`${g.rule}\` (${g.count})`);
    for (const item of g.entries) {
      const loc = item.file ? `${item.file}${item.line ? `:${item.line}` : ""}` : "n/a";
      out.push(`- **Location:** \`${loc}\` (${item.language ?? "unknown"}, ${item.runtime}, ${item.os})`);
      if (item.reason) out.push(`  - **Reason:** ${item.reason}`);
      if (item.finding) out.push(`  - **Finding:** \`${item.finding}\``);
      if (item.snippet) out.push(`\`\`\`${item.language ?? ""}`, item.snippet, "```");
    }
  }
  return out.join("\n");
}

export function flushLocalFeedbackQueue(options: FlushQueueOptions = {}): FlushQueueResult {
  if (!options || typeof options !== "object") throw new Error("FlushQueueOptions object is required.");
  const repoRoot = path.resolve(options.repoRoot ?? process.cwd());
  const absQueue = path.join(repoRoot, FEEDBACK_QUEUE_REL);
  if (!fs.existsSync(absQueue)) {
    return { queuePath: FEEDBACK_QUEUE_REL, rawCount: 0, uniqueCount: 0, groups: [], title: "[Roll-up] No queued feedback", label: "bug", markdown: "No queued feedback entries in .verification/tool-feedback.jsonl.", cleared: false };
  }
  const rawLines = fs.readFileSync(absQueue, "utf8").split(/\r?\n/).filter((l) => l.trim().length > 0);
  const seen = new Set<string>();
  const groupMap = new Map<string, FlushQueueGroup>();
  let uniqueCount = 0;
  for (const raw of rawLines) {
    let parsed: ToolReportEntry;
    try { parsed = JSON.parse(raw) as ToolReportEntry; } catch { continue; }
    const dedupeKey = `${parsed.kind}|${parsed.rule}|${parsed.file ?? ""}:${parsed.line ?? ""}|${parsed.reason}|${parsed.snippet ?? ""}`;
    if (seen.has(dedupeKey)) continue;
    seen.add(dedupeKey);
    uniqueCount += 1;
    const gKey = `${parsed.kind}::${parsed.rule || "general"}`;
    const existing = groupMap.get(gKey);
    if (existing) { existing.entries.push(parsed); existing.count += 1; }
    else groupMap.set(gKey, { key: gKey, kind: parsed.kind ?? "fp", rule: parsed.rule || "general", count: 1, entries: [parsed] });
  }
  const groups = [...groupMap.values()].sort((a, b) => (b.count !== a.count ? b.count - a.count : a.key.localeCompare(b.key)));
  const label: "false-positive" | "bug" = groups.every((g) => g.kind === "fp") ? "false-positive" : "bug";
  const title = `[Roll-up] ${uniqueCount} tool feedback item(s) across ${groups.length} rule(s)`;
  const markdown = formatRollupMarkdown(groups, uniqueCount, rawLines.length);
  let cleared = false;
  if (options.clear && fs.existsSync(absQueue)) { fs.rmSync(absQueue, { force: true }); cleared = true; }
  return { queuePath: FEEDBACK_QUEUE_REL, rawCount: rawLines.length, uniqueCount, groups, title, label, markdown, cleared };
}

function defaultGhRunner(args: readonly string[], timeoutMs: number): GhRunResult {
  const proc = spawnSync("gh", [...args], { encoding: "utf8", shell: false, timeout: timeoutMs });
  return { status: proc.status, stdout: proc.stdout ?? "", stderr: proc.stderr ?? "", error: proc.error };
}

function submitToGitHub(input: { kind: ReportKind; label: "false-positive" | "bug"; title: string; markdown: string }, ghRunner: GhRunner): { submitted: boolean; issueUrl?: string; reason?: string; fallbackUrl: string } {
  const { url: fallbackUrl } = buildIssueUrl({ kind: input.kind, title: input.title, body: input.markdown });
  const ver = ghRunner(["--version"], 5_000);
  if (ver.error || ver.status !== 0) return { submitted: false, reason: "GitHub CLI ('gh') is not installed or unavailable.", fallbackUrl };
  const auth = ghRunner(["auth", "status"], 8_000);
  if (auth.error || auth.status !== 0) return { submitted: false, reason: "GitHub CLI ('gh') is not authenticated (run 'gh auth login').", fallbackUrl };
  const created = ghRunner(["issue", "create", "-R", TARGET_REPO, "--label", input.label, "--title", input.title, "--body", input.markdown], 20_000);
  if (created.error || created.status !== 0) return { submitted: false, reason: (created.stderr || created.error?.message || "gh issue create failed").trim(), fallbackUrl };
  return { submitted: true, issueUrl: created.stdout.trim(), fallbackUrl };
}

function parseReportFlag(args: readonly string[], flag: string): string | undefined {
  for (let i = 0; i < args.length; i++) {
    const tok = args[i] ?? "";
    if (tok === flag) return args[i + 1];
    if (tok.startsWith(`${flag}=`)) return tok.slice(flag.length + 1);
  }
  return undefined;
}

function parseKindFlag(raw: string | undefined): ReportKind {
  if (!raw) return "fp";
  if (raw === "fp" || raw === "fn" || raw === "crash" || raw === "bug") return raw;
  throw new Error(`Invalid --kind "${raw}". Expected: fp | fn | crash | bug.`);
}

function emitReportAction(opts: {
  mode: "single" | "flush"; kind: ReportKind; title: string; label: "false-positive" | "bug"; markdown: string;
  asJson: boolean; asUrl: boolean; doSubmit: boolean; outPath?: string; repoRoot: string; clearOnSubmit?: boolean;
  meta: Record<string, unknown>; ghRunner: GhRunner;
}): number {
  if (!opts.title) throw new Error("Report title is required.");
  if (opts.outPath) {
    const dest = path.isAbsolute(opts.outPath) ? opts.outPath : path.resolve(opts.repoRoot, opts.outPath);
    fs.mkdirSync(path.dirname(dest), { recursive: true });
    fs.writeFileSync(dest, `${opts.markdown}\n`, "utf8");
  }
  if (opts.doSubmit) {
    const sub = submitToGitHub({ kind: opts.kind, label: opts.label, title: opts.title, markdown: opts.markdown }, opts.ghRunner);
    let cleared = false;
    if (sub.submitted && opts.clearOnSubmit) {
      const absQueue = path.join(opts.repoRoot, FEEDBACK_QUEUE_REL);
      if (fs.existsSync(absQueue)) { fs.rmSync(absQueue, { force: true }); cleared = true; }
    }
    if (opts.asJson) { console.log(JSON.stringify({ ...opts.meta, title: opts.title, label: opts.label, ...sub, ...(opts.clearOnSubmit ? { cleared } : {}) }, null, 2)); return sub.submitted ? 0 : 1; }
    if (sub.submitted) { console.log(`Submitted issue: ${sub.issueUrl}${cleared ? " (cleared local feedback queue)" : ""}`); return 0; }
    console.error(`Submit skipped: ${sub.reason}`);
    console.log(`Open pre-filled issue URL instead:\n${sub.fallbackUrl}`);
    return 1;
  }
  if (opts.asUrl) {
    const urlRes = buildIssueUrl({ kind: opts.kind, title: opts.title, body: opts.markdown });
    console.log(opts.asJson ? JSON.stringify({ ...opts.meta, title: opts.title, label: opts.label, ...urlRes }, null, 2) : urlRes.url);
    return 0;
  }
  if (opts.asJson) { console.log(JSON.stringify({ ...opts.meta, title: opts.title, label: opts.label, markdown: opts.markdown, ...(opts.outPath ? { outFile: opts.outPath } : {}) }, null, 2)); return 0; }
  console.log(opts.markdown);
  if (opts.outPath) console.log(`\nWrote redacted report to ${opts.outPath}`);
  else console.log(`\nDry-run preview (nothing sent). Next: re-run with --submit, --url, --out <file>${opts.mode === "single" ? ", or --local" : ", or --clear"}.`);
  return 0;
}

export function handleReportCli(rest: readonly string[], asJson: boolean, repoRoot = process.cwd(), ghRunner: GhRunner = defaultGhRunner): number {
  if (!Array.isArray(rest)) throw new Error("CLI args must be an array.");
  const absRoot = path.resolve(repoRoot);
  const doSubmit = rest.includes("--submit");
  const asUrl = rest.includes("--url");
  const outPath = parseReportFlag(rest, "--out");
  if (rest.includes("--flush")) {
    const flushed = flushLocalFeedbackQueue({ repoRoot: absRoot, clear: rest.includes("--clear") && !doSubmit });
    if (flushed.uniqueCount === 0) { console.log(asJson ? JSON.stringify(flushed, null, 2) : flushed.markdown); return 0; }
    return emitReportAction({
      mode: "flush", kind: flushed.label === "false-positive" ? "fp" : "bug", title: flushed.title, label: flushed.label, markdown: flushed.markdown,
      asJson, asUrl, doSubmit, outPath, repoRoot: absRoot, clearOnSubmit: true,
      meta: { mode: "flush", queuePath: flushed.queuePath, rawCount: flushed.rawCount, uniqueCount: flushed.uniqueCount, groups: flushed.groups, cleared: flushed.cleared },
      ghRunner,
    });
  }
  const kind = parseKindFlag(parseReportFlag(rest, "--kind"));
  const built = buildToolReport({
    repoRoot: absRoot, rule: parseReportFlag(rest, "--rule"), file: parseReportFlag(rest, "--file"), kind,
    reason: parseReportFlag(rest, "--reason"), command: parseReportFlag(rest, "--command"),
    anonymize: rest.includes("--anonymize"), noRerun: rest.includes("--no-rerun"),
  });
  if (rest.includes("--local")) {
    const queued = appendLocalFeedbackEntry(absRoot, built.entry);
    if (asJson) console.log(JSON.stringify({ mode: "local", ...queued, entry: built.entry, title: built.title }, null, 2));
    else console.log(`Queued scrubbed feedback in ${queued.queuePath} (${queued.queuedCount} total). Run 'vstack report --flush' to preview or submit a roll-up.`);
    return 0;
  }
  return emitReportAction({ mode: "single", kind, title: built.title, label: built.label, markdown: built.markdown, asJson, asUrl, doSubmit, outPath, repoRoot: absRoot, meta: { mode: "single", entry: built.entry }, ghRunner });
}
