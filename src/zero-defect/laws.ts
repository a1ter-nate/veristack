import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import type { DiscoveredRepo, ScannedFile } from "../discover.ts";
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

function hasCodeownersCoverage(repo: DiscoveredRepo, lawRel: string): boolean {
  const co = repo.files.find((f) => /(?:^|\/)codeowners$/i.test(f.rel));
  if (!co) return false;
  const lines = co.content
    .split(/\r?\n/)
    .map((l) => l.trim())
    .filter((l) => l.length > 0 && !l.startsWith("#"));
  for (const line of lines) {
    const pattern = line.split(/\s+/)[0] ?? "";
    const norm = pattern.replace(/^\/+/, "");
    if (norm === "*" || norm === lawRel || (norm.endsWith("/") && lawRel.startsWith(norm))) return true;
    if (norm.endsWith("*.bend") && lawRel.endsWith(".bend")) return true;
    if (norm.includes("LAWS.bend") && lawRel.endsWith("LAWS.bend")) return true;
  }
  return false;
}

function auditBendLawFile(
  file: ScannedFile,
  pairedProof: ScannedFile | undefined,
  findings: Finding[],
): number {
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

function auditJsonLawFile(
  file: ScannedFile,
  repo: DiscoveredRepo,
  findings: Finding[],
  verifiedBackends: LawCheckResult["verifiedBackends"],
  verify: boolean,
): number {
  try {
    const parsed = JSON.parse(file.content) as {
      laws?: Array<{ id?: string; witnessRef?: string; invariant?: string; verifyArgs?: string[] }>;
    };
    const laws = Array.isArray(parsed.laws) ? parsed.laws : [];
    const allPaths = new Set(repo.allRelPaths);
    for (const law of laws) {
      const id = law.id ?? "unnamed";
      if (!law.witnessRef || !allPaths.has(law.witnessRef)) {
        findings.push({
          id: `LAW:json-witness:${file.rel}:${id}`,
          rule: "laws-missing-witness",
          category: "oracle-lock",
          rung: "R3",
          severity: "error",
          file: file.rel,
          line: 1,
          message: `Executable law '${id}' in ${file.rel} references missing witness '${law.witnessRef ?? ""}'.`,
          fix: "Point witnessRef to an existing Bend 2 proof, Quint spec, Kani harness, or PBT/MBT test file.",
        });
        continue;
      }
      if (verify) {
        const ref = law.witnessRef;
        if (ref.endsWith(".bend")) {
          runBendVerdict(repo.root, ref, findings, verifiedBackends);
          continue;
        }
        const cmdArgs: [string, string[], string] | null =
          Array.isArray(law.verifyArgs) && law.verifyArgs.length > 0 && typeof law.verifyArgs[0] === "string"
            ? [law.verifyArgs[0], law.verifyArgs.slice(1), repo.root]
            : /\.(?:test|spec)\.[cm]?[jt]sx?$/.test(ref)
              ? ["bun", ["test", path.join(repo.root, ref)], repo.root]
              : /(?:^|\/)test_[^/]+\.py$|_test\.py$/.test(ref)
                ? ["pytest", [path.join(repo.root, ref)], repo.root]
                : ref.endsWith("_test.go")
                  ? ["go", ["test", "."], path.dirname(path.join(repo.root, ref))]
                  : null;
        if (cmdArgs) {
          const run = spawnSync(cmdArgs[0], cmdArgs[1], { cwd: cmdArgs[2], encoding: "utf8", timeout: 45_000 });
          if (run.error) {
            verifiedBackends.push({ file: ref, backend: cmdArgs[0], status: "skipped", detail: `${cmdArgs[0]} not on PATH` });
          } else if (run.status === 0) {
            verifiedBackends.push({ file: ref, backend: cmdArgs[0], status: "passed", detail: `law '${id}' witness passed` });
          } else {
            const detail = (run.stderr || run.stdout || "witness failed").trim().slice(0, 200);
            verifiedBackends.push({ file: ref, backend: cmdArgs[0], status: "failed", detail });
            findings.push({
              id: `LAW:witness-fail:${file.rel}:${id}`,
              rule: "laws-witness-execution-failed",
              category: "oracle-lock",
              rung: "R3",
              severity: "error",
              file: ref,
              line: 1,
              message: `Executable law '${id}' failed mechanical verification via ${cmdArgs[0]}: ${detail}`,
              fix: `Fix the implementation or witness ${ref} until the law passes deterministically.`,
            });
          }
        }
      }
    }
    return laws.length;
  } catch {
    findings.push({
      id: `LAW:invalid-json:${file.rel}`,
      rule: "laws-invalid-json",
      category: "oracle-lock",
      rung: "R1",
      severity: "error",
      file: file.rel,
      line: 1,
      message: `Law manifest ${file.rel} is not valid JSON.`,
      fix: "Fix JSON syntax with { laws: [{ id, invariant, witnessRef }] }.",
    });
    return 0;
  }
}

export function auditLaws(repo: DiscoveredRepo, options?: { verify?: boolean }): LawCheckResult {
  const findings: Finding[] = [];
  const lawFiles: string[] = [];
  const verifiedBackends: LawCheckResult["verifiedBackends"] = [];
  let declaredLaws = 0;

  const hasCodeowners = repo.files.some((f) => /(?:^|\/)codeowners$/i.test(f.rel));
  const filesByRel = new Map<string, ScannedFile>();
  for (const f of repo.files) filesByRel.set(f.rel, f);

  for (const file of repo.files) {
    if (!isLawFile(file.rel)) continue;
    const base = path.posix.basename(file.rel);
    const dir = path.posix.dirname(file.rel);
    const siblingLaws = dir === "." ? "LAWS.bend" : `${dir}/LAWS.bend`;
    if (base === "PROOF.bend" && filesByRel.has(siblingLaws)) {
      continue;
    }

    lawFiles.push(file.rel);

    if (hasCodeowners && !hasCodeownersCoverage(repo, file.rel) && !file.rel.startsWith("templates/")) {
      findings.push({
        id: `LAW:unowned:${file.rel}`,
        rule: "laws-unowned-by-codeowners",
        category: "oracle-lock",
        rung: "R0",
        severity: "error",
        file: file.rel,
        line: 1,
        message: `Law file ${file.rel} is not protected by CODEOWNERS — implementing agents could weaken invariants.`,
        fix: `Lock ${file.rel} (or .verification/laws/ / LAWS.bend) in CODEOWNERS so only human reviewers can modify laws.`,
      });
    }

    if (file.rel.endsWith(".bend")) {
      const siblingProofRel = dir === "." ? "PROOF.bend" : `${dir}/PROOF.bend`;
      const pairedProof = base === "LAWS.bend" ? filesByRel.get(siblingProofRel) : undefined;
      declaredLaws += auditBendLawFile(file, pairedProof, findings);
      if (options?.verify) {
        const targetRel = pairedProof ? pairedProof.rel : file.rel;
        runBendVerdict(repo.root, targetRel, findings, verifiedBackends);
      }
    } else if (file.rel.endsWith(".laws.json")) {
      declaredLaws += auditJsonLawFile(file, repo, findings, verifiedBackends, Boolean(options?.verify));
    }
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
