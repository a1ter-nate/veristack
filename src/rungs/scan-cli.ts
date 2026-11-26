import { spawnSync } from "node:child_process";
import fs from "node:fs";
import { discoverRepo } from "../discover.ts";
import { formatMarkdownReport, formatTerminalReport } from "../format.ts";
import { scanRepo } from "../ladder.ts";
import {
  buildRatchetBaseline,
  evaluateRatchet,
  type RatchetBaseline,
  writeRatchetBaseline,
} from "../ratchet.ts";
import type { RungId } from "../types.ts";
import { runPlantedFaultCanary } from "./mutation-probe.ts";
import { runAllDeclaredRungs } from "./receipts.ts";
import { evaluateCrapForCoverageFile } from "./reports.ts";
import { auditCodeownersPerimeter, checkGitHubBranchProtection } from "./workflow-audit.ts";

const VALID_RUNG_ARGS = new Set(["R0", "R1", "R2", "R3", "R4", "R5", "R6", "R7", "R8", "all"]);

function parseFlagValue(args: readonly string[], flag: string): string | undefined {
  const index = args.indexOf(flag);
  if (index < 0) return undefined;
  return args[index + 1];
}

function loadBaseline(repoRoot: string, ratchetPath: string, baseRef?: string): RatchetBaseline | undefined {
  if (baseRef) {
    const cleanPath = ratchetPath.replace(/^\.\//, "");
    const gitShow = spawnSync("git", ["-C", repoRoot, "show", `${baseRef}:${cleanPath}`], { encoding: "utf8" });
    if (gitShow.status !== 0) return undefined;
    return JSON.parse(gitShow.stdout) as RatchetBaseline;
  }
  if (!fs.existsSync(ratchetPath)) return undefined;
  return JSON.parse(fs.readFileSync(ratchetPath, "utf8")) as RatchetBaseline;
}

export function handleScanCli(rest: readonly string[], target: string, asJson: boolean, asMd: boolean): number {
  const strict = rest.includes("--strict");
  const allowMissingRungs = rest.includes("--allow-missing-rungs");
  const failOnPoorCoverage = rest.includes("--fail-on-poor-coverage");
  const configPath = parseFlagValue(rest, "--config");
  const disableRaw = parseFlagValue(rest, "--disable");
  const disableRules = disableRaw
    ? disableRaw.split(",").map((r) => r.trim()).filter(Boolean)
    : undefined;
  const ratchetPath = parseFlagValue(rest, "--ratchet");
  const ratchetBase = parseFlagValue(rest, "--ratchet-base");
  const updateRatchet = rest.includes("--update-ratchet");

  if (strict && (ratchetPath || updateRatchet || ratchetBase)) {
    console.error("vstack scan --strict forbids --ratchet, --ratchet-base, and --update-ratchet baselines.");
    return 1;
  }
  if (strict && (configPath || (disableRules && disableRules.length > 0))) {
    console.error("vstack scan --strict forbids --config and --disable rule overrides.");
    return 1;
  }
  if (strict && allowMissingRungs) {
    console.error("vstack scan --strict forbids --allow-missing-rungs.");
    return 1;
  }

  const report = scanRepo(target, { configPath, disableRules, strict });
  let ratchetEval: ReturnType<typeof evaluateRatchet> | undefined;

  if (ratchetPath) {
    if (updateRatchet) {
      const nextBaseline = buildRatchetBaseline(report.findings, report.rungs);
      writeRatchetBaseline(ratchetPath, nextBaseline);
      ratchetEval = evaluateRatchet(report.findings, nextBaseline, report.rungs);
    } else {
      const baseline = loadBaseline(report.repo, ratchetPath, ratchetBase);
      if (!baseline) {
        console.error(
          `vstack scan --ratchet failed: baseline '${ratchetPath}' not found${ratchetBase ? ` at ${ratchetBase}` : ""}. Refusing to auto-create passing baseline (pass --update-ratchet intentionally to initialize).`,
        );
        return 1;
      }
      ratchetEval = evaluateRatchet(report.findings, baseline, report.rungs);
    }
  }

  if (asJson) console.log(JSON.stringify(ratchetEval ? { ...report, ratchet: ratchetEval } : report, null, 2));
  else if (asMd) console.log(formatMarkdownReport(report));
  else {
    console.log(formatTerminalReport(report));
    if (ratchetEval) {
      console.log(`\nRATCHET (${ratchetPath}): ${ratchetEval.passed ? "PASS" : "FAIL"}`);
      for (const r of ratchetEval.regressions) {
        console.log(`  - [REGRESSION] ${r.rule}: ${r.baseline} -> ${r.current} (+${r.delta})`);
      }
      for (const t of ratchetEval.tightenAvailable) {
        console.log(`  - [TIGHTEN] ${t.rule}: ${t.baseline} -> ${t.current} (${t.delta}) — rerun with --update-ratchet`);
      }
      for (const rr of ratchetEval.rungRegressions) {
        console.log(`  - [RUNG REGRESSION] ${rr.rung}: ${rr.reason}`);
      }
    }
  }

  const s = report.summary;

  if (strict) {
    if (report.config) {
      console.error("vstack scan --strict failed: .vstack.json overrides/ignores are forbidden under --strict.");
      return 1;
    }
    if (s.excludedCount > 0) {
      console.error(
        `vstack scan --strict failed: ${s.excludedCount} unallowlisted excluded/ignored/oversized/minified/truncated path(s).`,
      );
      return 1;
    }
    if (
      s.totalFindings > 0 ||
      s.errorCount > 0 ||
      s.warnCount > 0 ||
      s.cheatCount > 0 ||
      s.noCommentCount > 0 ||
      s.holeCount > 0 ||
      s.poorlyCoveredCount > 0 ||
      s.unexecutedRungCount > 0 ||
      s.pushDownCount > 0
    ) {
      return 1;
    }
    return 0;
  }

  if (ratchetEval) {
    if (!ratchetEval.passed) return 1;
    if (!allowMissingRungs && (s.holeCount > 0 || s.unexecutedRungCount > 0)) {
      return 1;
    }
  } else if (!allowMissingRungs && (s.holeCount > 0 || s.unexecutedRungCount > 0)) {
    if (!asJson && !asMd) {
      console.error(
        `\nFAIL: ${s.holeCount} not-covered/over-budget rung(s) and ${s.unexecutedRungCount} rung(s) not executing in CI. Wire missing rungs into CI (or pass --allow-missing-rungs for snippet-only scans).`,
      );
    }
    return 1;
  }
  if (failOnPoorCoverage && s.poorlyCoveredCount > 0) return 1;
  if (rest.includes("--fail-on-errors") && s.errorCount > 0) return 1;
  if (rest.includes("--fail-on-cheats") && (s.cheatCount > 0 || s.noCommentCount > 0)) {
    return 1;
  }
  return 0;
}

export function handleRungToolsCli(cmd: string, rest: readonly string[], target: string, asJson: boolean): number | null {
  if (cmd === "run-rung") {
    const rungArg = rest[0] ?? "all";
    if (!VALID_RUNG_ARGS.has(rungArg)) {
      console.error(`Invalid rung '${rungArg}'. Expected R0..R8 or all.`);
      return 2;
    }
    const dirArg = rest[1] && !rest[1].startsWith("-") ? rest[1] : ".";
    const repo = discoverRepo(dirArg);
    const result = runAllDeclaredRungs(repo, rungArg as RungId | "all");
    if (asJson) {
      console.log(JSON.stringify(result, null, 2));
    } else {
      for (const r of result.receipts) {
        const canaryTag = r.canary ? ` | canary=${(r.canary.killRate * 100).toFixed(0)}% (${r.canary.killedMutants}/${r.canary.totalMutants})` : "";
        console.log(`run-rung ${r.rung}: ${r.exitCode === 0 ? "PASS" : "FAIL"} (${r.durationMs}ms${canaryTag}) -> .verification/receipts/${r.rung}.json`);
      }
    }
    return result.passed ? 0 : 1;
  }

  if (cmd === "canary") {
    const testCmd = parseFlagValue(rest, "--test-cmd");
    if (!testCmd) {
      throw new Error("vstack canary requires --test-cmd <command>.");
    }
    const targetsRaw = parseFlagValue(rest, "--targets");
    const targets = targetsRaw ? targetsRaw.split(",").map((t) => t.trim()).filter(Boolean) : undefined;
    const baseRef = parseFlagValue(rest, "--base");
    const maxRaw = parseFlagValue(rest, "--max-mutants");
    const minRateRaw = parseFlagValue(rest, "--min-kill-rate");
    const report = runPlantedFaultCanary({
      repoRoot: target,
      testCmd,
      targets,
      baseRef,
      maxMutants: maxRaw ? Number(maxRaw) : undefined,
      minKillRate: minRateRaw ? Number(minRateRaw) : undefined,
    });
    if (asJson) {
      console.log(JSON.stringify(report, null, 2));
    } else {
      console.log(
        `canary [${report.passed ? "PASS" : "FAIL"}]: killed=${report.killedMutants}/${report.totalMutants} (${(report.killRate * 100).toFixed(1)}%, floor=${(report.minKillRate * 100).toFixed(0)}%, invalid=${report.invalidKills})`,
      );
      for (const s of report.survivors) {
        console.log(`  - [SURVIVED] ${s.file}:${s.line} (${s.operator}) — ${s.original}`);
      }
    }
    return rest.includes("--fail") && !report.passed ? 1 : 0;
  }

  if (cmd === "perimeter") {
    const repo = discoverRepo(target);
    const co = auditCodeownersPerimeter(repo.files, repo.allRelPaths);
    const gh = rest.includes("--check-github") ? checkGitHubBranchProtection(repo.root) : undefined;
    const passed = co.passed && (!gh || gh.passed);
    if (asJson) {
      console.log(JSON.stringify({ passed, codeowners: co, branchProtection: gh }, null, 2));
    } else {
      console.log(`perimeter [${passed ? "PASS" : "FAIL"}]: CODEOWNERS=${co.passed ? "LOCKED" : `UNCOVERED (${co.uncoveredSurfaces.join(", ")})`}`);
      if (gh) console.log(`  GitHub branch protection: ${gh.passed ? "PASS" : "FAIL"} — ${gh.detail}`);
    }
    return rest.includes("--fail") && !passed ? 1 : 0;
  }

  if (cmd === "crap") {
    const covPath = parseFlagValue(rest, "--coverage");
    if (!covPath) {
      throw new Error("vstack crap requires --coverage <lcov.info|cobertura.xml>.");
    }
    const maxRaw = parseFlagValue(rest, "--max-crap");
    const report = evaluateCrapForCoverageFile(target, covPath, maxRaw ? Number(maxRaw) : 30);
    if (asJson) {
      console.log(JSON.stringify(report, null, 2));
    } else {
      console.log(
        `crap [${report.passed ? "PASS" : "FAIL"}]: evaluated=${report.evaluatedFiles} worst=${report.worstCrap} maxAllowed=${report.maxAllowed} offenders=${report.offenders.length}`,
      );
      for (const o of report.offenders.slice(0, 20)) {
        console.log(`  - ${o.file}: CRAP=${o.crapScore} (CC=${o.cyclomaticComplexity}, cov=${o.coveragePct}%)`);
      }
    }
    return rest.includes("--fail") && !report.passed ? 1 : 0;
  }

  return null;
}
