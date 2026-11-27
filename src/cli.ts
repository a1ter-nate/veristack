import { runCli } from "@veristack/core";

runCli(process.argv.slice(2))
  .then((code) => {
    process.exitCode = code;
  })
  .catch((err: unknown) => {
    const message = err instanceof Error ? err.message : String(err);
    console.error(`vstack error: ${message}`);
    process.exitCode = 1;
  });
