import fs from "node:fs";
import { formatSingleFileReport, scanSingleFile, type CheckFileTier } from "./check-file.ts";
import { formatDoctorReport, runDoctor } from "./doctor.ts";
import { formatHooksStatus, type HooksAdminAction, manageHooks } from "./install.ts";
import { executeHookEvent, type HookEventKind, type HookHarness } from "./runtime.ts";

function parseFlag(args: readonly string[], flag: string): string | undefined {
  const idx = args.indexOf(flag);
  return idx >= 0 ? args[idx + 1] : undefined;
}

function parseHarness(raw: string | undefined): HookHarness | undefined {
  if (raw === "claude" || raw === "codex" || raw === "cursor" || raw === "copilot" || raw === "grok") return raw;
  return undefined;
}

function parseTier(raw: string | undefined): CheckFileTier | undefined {
  if (raw === "immediate" || raw === "all") return raw;
  return undefined;
}

function readStdinSync(): string {
  try {
    if (process.stdin.isTTY) return "";
    return fs.readFileSync(0, "utf8");
  } catch {
    return "";
  }
}

export function handleHooksAndDoctorCli(
  cmd: string,
  rest: readonly string[],
  target: string,
  asJson: boolean,
): number | null {
  if (cmd === "check-file") {
    const fileArg = rest.find((a) => !a.startsWith("-"));
    if (!fileArg) throw new Error("vstack check-file requires a file path.");
    const tier = parseTier(parseFlag(rest, "--tier")) ?? "immediate";
    const maxRaw = parseFlag(rest, "--max-lines");
    const result = scanSingleFile(fileArg, {
      tier,
      strict: rest.includes("--strict"),
      maxLines: maxRaw ? Number(maxRaw) : undefined,
    });
    if (asJson) console.log(JSON.stringify(result, null, 2));
    else console.log(formatSingleFileReport(result));
    return rest.includes("--fail") && result.findings.length > 0 ? 1 : 0;
  }

  if (cmd === "hook") {
    const sub = rest[0];
    if (sub !== "post-edit" && sub !== "pre-edit" && sub !== "stop") {
      throw new Error("vstack hook requires subcommand: post-edit | pre-edit | stop.");
    }
    const event: HookEventKind = sub;
    const harness = parseHarness(parseFlag(rest, "--harness"));
    const tier = parseTier(parseFlag(rest, "--tier"));
    const rawStdin = readStdinSync();
    const res = executeHookEvent(event, rawStdin, { repoRoot: process.cwd(), harness, tier });
    if (res.stdout) console.log(res.stdout);
    return res.exitCode;
  }

  if (cmd === "hooks") {
    const rawAction = rest[0] && !rest[0].startsWith("-") ? rest[0] : "status";
    if (rawAction !== "on" && rawAction !== "off" && rawAction !== "status" && rawAction !== "reset") {
      throw new Error(`Unsupported hooks action "${rawAction}". Expected: on | off | status | reset.`);
    }
    const action: HooksAdminAction = rawAction;
    const dirArg = rest.slice(1).find((a) => !a.startsWith("-")) ?? ".";
    const harnessesRaw = parseFlag(rest, "--harness");
    const harnesses = harnessesRaw
      ? harnessesRaw.split(",").map((s) => parseHarness(s.trim())).filter((h): h is HookHarness => Boolean(h))
      : undefined;
    const commandPrefix = parseFlag(rest, "--command");
    const res = manageHooks(dirArg, action, { harnesses, commandPrefix });
    if (asJson) console.log(JSON.stringify(res, null, 2));
    else console.log(formatHooksStatus(res));
    return 0;
  }

  if (cmd === "doctor") {
    const report = runDoctor(target);
    if (asJson) console.log(JSON.stringify(report, null, 2));
    else console.log(formatDoctorReport(report));
    return rest.includes("--fail") && !report.healthy ? 1 : 0;
  }

  return null;
}
