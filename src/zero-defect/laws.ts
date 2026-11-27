import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import type { DiscoveredRepo, ScannedFile } from "../discover.ts";
import { parseAndValidateCommandArgv } from "../rungs/command-audit.ts";
import { globMatchesPath } from "../rungs/workflow-audit.ts";
import { lineOf } from "../test-lexical.ts";
import type { Finding } from "../types.ts";

export interface LawCheckResult {
  lawFiles: string[];
  declaredLaws: number;
  verifiedBackends: Array<{ file: string; backend: string; status: "passed" | "failed" | "skipped"; detail: string }>;
  findings: Finding[];
}

const BEND_LAW_DECL = /^\s*(?:law|theorem)\s+([A-Za-z_][A-Za-z0-9_]*)\b/gm;
const BEND_DEF_DECL = /^\s*def\s+(?:[A-Za-z_][A-Za-z0-9_]*\.)?([A-Za-z_][A-Za-z0-9_]*)\b/gm;
const BEND_UNSAFE_ESCAPE = /(?:@unsafe\b|\?[A-Za-z_][A-Za-z0-9_]*|\b(?:unsafe|sorry|admit|todo!|panic!)\b)/g;

function resolveBendBinary(): string {
  const localBin = path.join(os.homedir(), ".bend", "bin", "bend");
  if (fs.existsSync(localBin)) return localBin;
  return "bend";
}

function isLawFile(rel: string): boolean {
  const base = path.posix.basename(rel);
  return (
    base === "LAWS.bend" ||
    base === "PROOF.bend" ||
    base.endsWith(".laws.bend") ||
    base.endsWith(".laws.json") ||
    /(?:^|\/)\.verification\/laws\//.test(rel)
  );
}

function findPrimaryCodeowners(repo: DiscoveredRepo): ScannedFile | undefined {
  let rootMatch: ScannedFile | undefined;
  let docsMatch: ScannedFile | undefined;
  for (const f of repo.files) {
    if (f.rel === ".github/CODEOWNERS") return f;
    if (f.rel === "CODEOWNERS") rootMatch = f;
    else if (f.rel === "docs/CODEOWNERS") docsMatch = f;
  }
  return rootMatch ?? docsMatch;
}

function hasCodeownersCoverage(repo: DiscoveredRepo, lawRel: string): boolean {
  const co = findPrimaryCodeowners(repo);
  if (!co) return false;
  const lines = co.content
    .split(/\r?\n/)
    .map((l) => l.trim())
    .filter((l) => l.length > 0 && !l.startsWith("#"));
  let lastOwners: string[] | null = null;
  for (const line of lines) {
    const parts = line.split(/\s+/);
    const pattern = parts[0] ?? "";
    const owners = parts.slice(1).filter((o) => /^@[A-Za-z0-9_.-]+(?:\/[A-Za-z0-9_.-]+)?$|^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(o));
    if (globMatchesPath(pattern, lawRel)) lastOwners = owners;
  }
  return Boolean(lastOwners && lastOwners.length > 0);
}

function auditBendLawFile(
  file: ScannedFile,
  pairedProof: ScannedFile | undefined,
  findings: Finding[],
): number {
  if (!file.content) return 0;
  if (!Array.isArray(findings)) throw new Error("Findings array is required.");
  const declared: Array<{ name: string; offset: number }> = [];
  for (const m of file.content.matchAll(BEND_LAW_DECL)) {
    if (m[1]) declared.push({ name: m[1], offset: m.index ?? 0 });
  }
  const defs = new Set<string>();
  const defSource = pairedProof ? `${file.content}\n${pairedProof.content}` : file.content;
  for (const m of defSource.matchAll(BEND_DEF_DECL)) {
    if (m[1]) defs.add(m[1]);
  }
  for (const law of declared) {
    if (!defs.has(law.name)) {
      const line = lineOf(file.content, law.offset);
      findings.push({
        id: `LAW:missing-witness:${file.rel}:${line}`,
        rule: "laws-missing-witness",
        category: "oracle-lock",
        rung: "R5",
        severity: "error",
        file: file.rel,
        line,
        message: `Bend 2 law '${law.name}' has no matching constructive proof definition ('def ${law.name}' or paired PROOF.bend).`,
        fix: `Provide a total proof function proving '${law.name}' and verify with 'bend PROOF.bend --verdict'.`,
      });
    }
  }
  const escapeFiles = pairedProof ? [file, pairedProof] : [file];
  for (const ef of escapeFiles) {
    for (const m of ef.content.matchAll(BEND_UNSAFE_ESCAPE)) {
      const line = lineOf(ef.content, m.index ?? 0);
      findings.push({
        id: `LAW:unsafe-escape:${ef.rel}:${line}`,
        rule: "laws-bend-unsafe-escape",
        category: "cheat",
        rung: "R0",
        severity: "error",
        file: ef.rel,
        line,
        message: `Proof escape hatch '${m[0]}' inside Bend 2 file undermines mechanical verification.`,
        fix: "Complete the constructive proof without @unsafe, ?holes, sorry, or admit escapes.",
      });
    }
  }
  return declared.length;
}

function runBendVerdict(
  repoRoot: string,
  relPath: string,
  findings: Finding[],
  verifiedBackends: LawCheckResult["verifiedBackends"],
): void {
  if (!repoRoot) throw new Error("repoRoot is required for Bend verdict.");
  if (!relPath) throw new Error("relPath is required for Bend verdict.");
  const bendBin = resolveBendBinary();
  const absFile = path.join(repoRoot, relPath);
  const useKernel = Boolean(process.env.BENDTT);
  const flag = useKernel ? "--verdict" : "--check-only";
  const probe = spawnSync(bendBin, [absFile, flag], {
    cwd: path.dirname(absFile),
    encoding: "utf8",
    timeout: 30_000,
  });
  if (probe.error) {
    verifiedBackends.push({ file: relPath, backend: "bend2", status: "failed", detail: "bend CLI not installed on PATH (fail-closed under --verify)" });
    findings.push({
      id: `LAW:bend-missing:${relPath}`,
      rule: "laws-verifier-missing",
      category: "oracle-lock",
      rung: "R5",
      severity: "error",
      file: relPath,
      line: 1,
      message: `Bend 2 CLI ('bend') is not installed; cannot mechanically verify ${relPath} under --verify.`,
      fix: "Install the Bend 2 CLI so 'vstack laws --verify' proves every law instead of skipping.",
    });
    return;
  }
  const combined = `${probe.stdout ?? ""}\n${probe.stderr ?? ""}`;
  if (probe.status === 0 && /ALL PROOFS CHECK/i.test(combined)) {
    verifiedBackends.push({ file: relPath, backend: "bend2", status: "passed", detail: `bend ${flag}: ALL PROOFS CHECK` });
  } else {
    const detail = combined.trim().slice(0, 220) || `bend exited with status ${probe.status}`;
    verifiedBackends.push({ file: relPath, backend: "bend2", status: "failed", detail });
    findings.push({
      id: `LAW:bend-fail:${relPath}`,
      rule: "laws-bend-check-failed",
      category: "oracle-lock",
      rung: "R5",
      severity: "error",
      file: relPath,
      line: 1,
      message: `Bend 2 proof verification failed for ${relPath}: ${detail}`,
      fix: `Fix the failing Bend 2 proof until 'bend ${relPath} ${flag}' prints ALL PROOFS CHECK.`,
    });
  }
}

interface JsonLawEntry {
  id?: string;
  witnessRef?: string;
  invariant?: string;
  verifyArgs?: string[];
}

interface JsonLawAuditCtx {
  findings: Finding[];
  verifiedBackends: LawCheckResult["verifiedBackends"];
  verify: boolean;
}

function resolveLawCommand(
  law: JsonLawEntry,
  meta: { ref: string; fileRel: string; id: string; repoRoot: string },
  findings: Finding[],
): [string, string[], string] | "invalid" | null {
  if (!meta.ref) return null;
  if (Array.isArray(law.verifyArgs) && law.verifyArgs.length > 0 && typeof law.verifyArgs[0] === "string") {
    const rawCmd = law.verifyArgs.map((a) => (/\s/.test(a) ? `"${a}"` : a)).join(" ");
    const validated = parseAndValidateCommandArgv("canary", rawCmd, meta.repoRoot);
    const normRef = meta.ref.replace(/\\/g, "/").replace(/^\.\//, "");
    const refDir = path.posix.dirname(normRef);
    const isSingleFileTest = /\.(?:test|spec)\.[cm]?[jt]sx?$|_test\.py$|(?:^|\/)test_[^/]+\.py$/i.test(normRef);
    const mentionsWitness = law.verifyArgs.some((a) => {
      const normA = a.replace(/\\/g, "/").replace(/^\.\//, "").replace(/\/+$/, "");
      if (!normA || normA.startsWith("-")) return false;
      if (normA === normRef) return true;
      if (isSingleFileTest) return false;
      if (refDir !== "." && normA === refDir) return true;
      if (/(?:Cargo\.toml|\.csproj|\.slnx|pyproject\.toml)$/i.test(normA)) {
        const manifestDir = path.posix.dirname(normA);
        if (manifestDir !== "." && normRef.startsWith(`${manifestDir}/`)) return true;
      }
      return normA !== "." && !/\.[A-Za-z0-9]+$/.test(normA) && normRef.startsWith(`${normA}/`);
    });
    if (validated.error || validated.steps.length !== 1 || !mentionsWitness) {
      findings.push({
        id: `LAW:invalid-runner:${meta.fileRel}:${meta.id}`, rule: "laws-invalid-verifier", category: "oracle-lock", rung: "R3", severity: "error",
        file: meta.fileRel, line: 1,
        message: `Executable law '${meta.id}' declares disallowed verifyArgs ('${law.verifyArgs.join(" ")}'): ${validated.error ?? `must reference witness '${meta.ref}'`}.`,
        fix: "Use a bare allowlisted test/formal verifier referencing the witness path with safe flags only.",
      });
      return "invalid";
    }
    return [law.verifyArgs[0], law.verifyArgs.slice(1), meta.repoRoot];
  }
  if (/\.(?:test|spec)\.[cm]?[jt]sx?$/.test(meta.ref)) return ["bun", ["test", path.join(meta.repoRoot, meta.ref)], meta.repoRoot];
  if (/(?:^|\/)test_[^/]+\.py$|_test\.py$/.test(meta.ref)) return ["pytest", [path.join(meta.repoRoot, meta.ref)], meta.repoRoot];
  if (meta.ref.endsWith("_test.go")) return ["go", ["test", "-count=1", "-v", "."], path.dirname(path.join(meta.repoRoot, meta.ref))];
  return null;
}

function executeLawWitness(
  cmdArgs: [string, string[], string],
  meta: { ref: string; fileRel: string; id: string },
  ctx: JsonLawAuditCtx,
): void {
  if (!cmdArgs[0]) throw new Error("Missing law verifier executable.");
  const run = spawnSync(cmdArgs[0], cmdArgs[1], { cwd: cmdArgs[2], shell: false, encoding: "utf8", timeout: 45_000 });
  const out = `${run.stdout ?? ""}\n${run.stderr ?? ""}`;
  const cargoPassedSum = [...out.matchAll(/test result:\s*ok\.\s*(\d+)\s+passed/gi)].reduce((acc, m) => acc + Number(m[1] ?? 0), 0);
  const dotnetPassedSum = [...out.matchAll(/\bPassed:\s*(\d+)/gi)].reduce((acc, m) => acc + Number(m[1] ?? 0), 0);
  const hasPositivePass = cargoPassedSum > 0 || dotnetPassedSum > 0 || /^\s*[1-9]\d*\s+pass\b|\b[1-9]\d*\s+passed\b|^---\s+PASS:|^\s*(?:ℹ|#)\s*pass\s+[1-9]\d*/im.test(out);
  const zeroTests = !hasPositivePass && (/(?:\b0\s+pass\b|\b0\s+passed\b|\bcollected\s+0\s+items\b|\[no\s+tests\s+to\s+run\]|\bno\s+tests\s+found\b|\b0\s+tests?\s+ran\b)/i.test(out) || /^\s*$/.test(out) || /^(?:bun|node|pytest|vitest|jest|cargo|dotnet|go)$/i.test(cmdArgs[0]));
  if (run.error) {
    ctx.verifiedBackends.push({ file: meta.ref, backend: cmdArgs[0], status: "failed", detail: `${cmdArgs[0]} not on PATH` });
    ctx.findings.push({
      id: `LAW:verifier-missing:${meta.fileRel}:${meta.id}`, rule: "laws-verifier-missing", category: "oracle-lock", rung: "R3", severity: "error",
      file: meta.ref, line: 1,
      message: `Executable law '${meta.id}' could not be verified: runner '${cmdArgs[0]}' not found on PATH.`,
      fix: `Install '${cmdArgs[0]}' in CI so --verify executes every law witness without fail-open skips.`,
    });
    return;
  }
  if (run.status === 0 && !zeroTests) {
    ctx.verifiedBackends.push({ file: meta.ref, backend: cmdArgs[0], status: "passed", detail: `law '${meta.id}' witness passed` });
    return;
  }
  const detail = zeroTests ? `witness executed 0 tests (${out.trim().slice(0, 120) || "empty output"})` : (run.stderr || run.stdout || "witness failed").trim().slice(0, 200);
  ctx.verifiedBackends.push({ file: meta.ref, backend: cmdArgs[0], status: "failed", detail });
  ctx.findings.push({
    id: `LAW:witness-fail:${meta.fileRel}:${meta.id}`, rule: zeroTests ? "laws-witness-zero-tests" : "laws-witness-execution-failed", category: "oracle-lock", rung: "R3", severity: "error",
    file: meta.ref, line: 1,
    message: `Executable law '${meta.id}' failed mechanical verification via ${cmdArgs[0]}: ${detail}`,
    fix: `Fix the implementation or witness ${meta.ref} until the law executes >0 tests and passes deterministically.`,
  });
}

function auditJsonLawFile(file: ScannedFile, repo: DiscoveredRepo, ctx: JsonLawAuditCtx): number {
  let parsed: { laws?: JsonLawEntry[] };
  try { parsed = JSON.parse(file.content) as { laws?: JsonLawEntry[] }; } catch {
    ctx.findings.push({ id: `LAW:invalid-json:${file.rel}`, rule: "laws-invalid-json", category: "oracle-lock", rung: "R1", severity: "error", file: file.rel, line: 1, message: `Law manifest ${file.rel} is not valid JSON.`, fix: "Fix JSON syntax with { laws: [{ id, invariant, witnessRef }] }." });
    return 0;
  }
  const laws = Array.isArray(parsed.laws) ? parsed.laws : [];
  const allPaths = new Set(repo.allRelPaths);
  for (const law of laws) {
    const id = law.id ?? "unnamed";
    if (!law.witnessRef || !allPaths.has(law.witnessRef)) {
      ctx.findings.push({ id: `LAW:json-witness:${file.rel}:${id}`, rule: "laws-missing-witness", category: "oracle-lock", rung: "R3", severity: "error", file: file.rel, line: 1, message: `Executable law '${id}' in ${file.rel} references missing witness '${law.witnessRef ?? ""}'.`, fix: "Point witnessRef to an existing Bend 2 proof, Quint spec, Kani harness, or PBT/MBT test file." });
      continue;
    }
    if (!ctx.verify) continue;
    const ref = law.witnessRef;
    if (ref.endsWith(".bend")) { runBendVerdict(repo.root, ref, ctx.findings, ctx.verifiedBackends); continue; }
    const cmdArgs = resolveLawCommand(law, { ref, fileRel: file.rel, id, repoRoot: repo.root }, ctx.findings);
    if (cmdArgs === "invalid") continue;
    if (!cmdArgs) {
      ctx.verifiedBackends.push({ file: ref, backend: "none", status: "failed", detail: "no executable witness runner" });
      ctx.findings.push({ id: `LAW:unverifiable:${file.rel}:${id}`, rule: "laws-unverifiable-witness", category: "oracle-lock", rung: "R3", severity: "error", file: file.rel, line: 1, message: `Executable law '${id}' witness '${ref}' has no runnable verifier backend under --verify.`, fix: "Point witnessRef to a .bend/.test.*/test_*.py/*_test.go witness or specify allowlisted verifyArgs." });
      continue;
    }
    executeLawWitness(cmdArgs, { ref, fileRel: file.rel, id }, ctx);
  }
  return laws.length;
}

export function auditLaws(repo: DiscoveredRepo, options?: { verify?: boolean }): LawCheckResult {
  if (!repo.root) throw new Error("repo.root is required to audit laws.");
  if (!Array.isArray(repo.files)) throw new Error("repo.files must be an array.");
  const findings: Finding[] = [];
  const lawFiles: string[] = [];
  const verifiedBackends: LawCheckResult["verifiedBackends"] = [];
  let declaredLaws = 0;

  const hasCodeowners = Boolean(findPrimaryCodeowners(repo));
  const filesByRel = new Map<string, ScannedFile>();
  for (const f of repo.files) filesByRel.set(f.rel, f);

  for (const file of repo.files) {
    if (!isLawFile(file.rel)) continue;
    const base = path.posix.basename(file.rel);
    const dir = path.posix.dirname(file.rel);
    const siblingLaws = dir === "." ? "LAWS.bend" : `${dir}/LAWS.bend`;
    if (base === "PROOF.bend" && filesByRel.has(siblingLaws)) continue;

    lawFiles.push(file.rel);
    if ((hasCodeowners || options?.verify) && !hasCodeownersCoverage(repo, file.rel)) {
      findings.push({
        id: `LAW:unowned:${file.rel}`, rule: "laws-unowned-by-codeowners", category: "oracle-lock", rung: "R0", severity: "error",
        file: file.rel, line: 1,
        message: `Law file ${file.rel} is not protected by CODEOWNERS — implementing agents could weaken invariants.`,
        fix: `Lock ${file.rel} (or .verification/laws/ / LAWS.bend) in CODEOWNERS so only human reviewers can modify laws.`,
      });
    }

    if (file.rel.endsWith(".bend")) {
      const siblingProofRel = dir === "." ? "PROOF.bend" : `${dir}/PROOF.bend`;
      const pairedProof = base === "LAWS.bend" ? filesByRel.get(siblingProofRel) : undefined;
      declaredLaws += auditBendLawFile(file, pairedProof, findings);
      if (options?.verify) runBendVerdict(repo.root, pairedProof ? pairedProof.rel : file.rel, findings, verifiedBackends);
    } else if (file.rel.endsWith(".laws.json")) {
      declaredLaws += auditJsonLawFile(file, repo, { findings, verifiedBackends, verify: Boolean(options?.verify) });
    }
  }

  if (options?.verify && declaredLaws === 0) {
    findings.push({
      id: "LAW:empty:.verification/laws", rule: "laws-empty", category: "oracle-lock", rung: "R3", severity: "error",
      file: ".verification/laws", line: 1,
      message: "vstack laws --verify found 0 declared laws to verify — failing closed.",
      fix: "Declare executable laws in .verification/laws/*.laws.json or LAWS.bend before running laws --verify.",
    });
  }

  return { lawFiles, declaredLaws, verifiedBackends, findings };
}

export function formatLawsReport(result: LawCheckResult): string {
  const lines = [
    `laws: ${result.lawFiles.length} law file(s), ${result.declaredLaws} declared law(s), ${result.findings.length} finding(s).`,
  ];
  for (const b of result.verifiedBackends) {
    lines.push(`  [${b.status.toUpperCase()}] ${b.backend} ${b.file} — ${b.detail}`);
  }
  for (const f of result.findings) {
    lines.push(`  - [${f.severity.toUpperCase()}] ${f.rule} ${f.file}:${f.line} — ${f.message}\n      Fix: ${f.fix}`);
  }
  return lines.join("\n");
}
