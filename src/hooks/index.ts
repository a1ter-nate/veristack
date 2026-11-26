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

function sleepMsSync(ms: number): void {
  try {
    Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);
  } catch {
    const end = performance.now() + ms;
    while (performance.now() < end) void 0;
  }
}

function readStdinBlocking(timeoutMs = 5000): { content: string; error?: string } {
  const chunks: Buffer[] = [];
  const buf = Buffer.alloc(65_536);
  const deadline = performance.now() + timeoutMs;
  for (;;) {
    try {
      const n = fs.readSync(0, buf, 0, buf.length, null);
      if (n === 0) break;
      chunks.push(Buffer.from(buf.subarray(0, n)));
    } catch (err: unknown) {
      const code = (err as NodeJS.ErrnoException | undefined)?.code;
      if (code === "EAGAIN" || code === "EWOULDBLOCK" || code === "EINTR") {
        if (performance.now() >= deadline) {
          return { content: Buffer.concat(chunks).toString("utf8"), error: "stdin read timed out (EAGAIN)" };
        }
        sleepMsSync(5);
        continue;
      }
      if (code === "EOF") break;
      return { content: Buffer.concat(chunks).toString("utf8"), error: `stdin read failed (${code ?? "unknown"})` };
    }
  }
  return { content: Buffer.concat(chunks).toString("utf8") };
}

function firstPositionalArg(args: readonly string[], valueFlags: ReadonlySet<string>): string | undefined {
  for (let i = 0; i < args.length; i++) {
    const a = args[i] ?? "";
    if (valueFlags.has(a)) {
      i += 1;
      continue;
    }
    if (!a.startsWith("-")) return a;
  }
  return undefined;
}

export function handleHooksAndDoctorCli(
  cmd: string,
  rest: readonly string[],
  target: string,
  asJson: boolean,
): number | null {
  if (cmd === "check-file") {
    const fileArg = firstPositionalArg(rest, new Set(["--tier", "--max-lines"]));
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
    const stdin = readStdinBlocking();
    const rawStdin = stdin.error && !stdin.content.trim() ? "__VSTACK_STDIN_READ_ERROR__" : stdin.content;
    const res = executeHookEvent(event, rawStdin, { repoRoot: process.cwd(), harness, tier });
    if (res.stderr) console.error(res.stderr);
    if (res.stdout) console.log(res.stdout);
    return res.exitCode;
  }

  if (cmd === "hooks") {
    const rawAction = rest[0] && !rest[0].startsWith("-") ? rest[0] : "status";
    if (rawAction !== "on" && rawAction !== "off" && rawAction !== "status" && rawAction !== "reset") {
      throw new Error(`Unsupported hooks action "${rawAction}". Expected: on | off | status | reset.`);
    }
    const action: HooksAdminAction = rawAction;
    const dirArg = firstPositionalArg(rest.slice(1), new Set(["--harness", "--command"])) ?? ".";
    const harnessesRaw = parseFlag(rest, "--harness");
    const harnesses = harnessesRaw
      ? harnessesRaw.split(",").map((s) => parseHarness(s.trim())).filter((h): h is HookHarness => Boolean(h))
      : undefined;
    const commandPrefix = parseFlag(rest, "--command");
    const res = manageHooks(dirArg, action, { harnesses, commandPrefix });
    if (asJson) console.log(JSON.stringify(res, null, 2));
    else console.log(formatHooksStatus(res));
    if (action === "status" && rest.includes("--fail") && !res.enabled) return 1;
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
