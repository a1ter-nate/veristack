import { runCli } from "@veristack/core";

runCli(process.argv.slice(2))
  .then((code) => {
    process.exitCode = code;
  })
  .catch((err: unknown) => {
    const message = err instanceof Error ? err.message : String(err);
    console.error(`vstack error: ${message}`);
    if (!process.argv.includes("--json")) {
      console.error('False positive or tool bug? Run: vstack report --kind crash --reason "<summary>"');
    }
    process.exitCode = 1;
  });
