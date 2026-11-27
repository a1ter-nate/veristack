import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { scanGitDiffCheats } from "@veristack/plugin-ci-auditor";
import { perfArchitectureAdvisorCircuit, type PerfAdvisorInput } from "@veristack/plugin-circuits";
import { runCircuit, type System1DecisionEngine } from "@veristack/plugin-circuits";
import { scanRepo } from "@veristack/core";
import { fitEmpiricalBigO, measureEmpiricalBigO } from "@veristack/plugin-zero-defect";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..", "..", "..");
const cliPath = path.join(repoRoot, "src", "cli.ts");

test("V42 deterministic perf-hygiene lints catch O(N^2) loop scans/shifts, N+1 I/O, loop regex/deepcopy, and GC tampering across TS/C#/Rust/Python", () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "vstack-perf-lints-"));
  try {
    fs.writeFileSync(
      path.join(tmp, "slow.ts"),
      [
        "export async function processAll(queue: string[], items: Array<{ id: string }>) {",
        "  while (queue.length > 0) {",
        "    const id = queue.shift();",
        "    const hit = items.find((x) => x.id === id);",
        "    const re = new RegExp(id ?? '');",
        "    const copy = JSON.parse(JSON.stringify(hit));",
        "    await fetch(`/api/${id}`);",
        "    void re; void copy;",
        "  }",
        "}",
      ].join("\n"),
    );

    fs.writeFileSync(
      path.join(tmp, "slow.py"),
      [
        "import copy, gc, re",
        "def process_all(queue, cursor):",
        "    gc.disable()",
        "    while queue:",
        "        item = queue.pop(0)",
        "        pat = re.compile(item)",
        "        cloned = copy.deepcopy(item)",
        "        cursor.execute('SELECT 1')",
        "    return pat, cloned",
      ].join("\n"),
    );

    fs.writeFileSync(
      path.join(tmp, "Slow.cs"),
      [
        "using System.Text.RegularExpressions;",
        "public sealed class S {",
        "  public async Task Run(List<string> items, HttpClient http) {",
        "    for (int i = 0; i < items.Count; i++) {",
        "      items.RemoveAt(0);",
        "      var r = new Regex(items[0]);",
        "      await http.GetAsync(\"/x\");",
        "    }",
        "  }",
        "}",
      ].join("\n"),
    );

    fs.writeFileSync(
      path.join(tmp, "slow.rs"),
      [
        "pub fn run(mut items: Vec<String>) {",
        "    while !items.is_empty() {",
        "        let _ = items.remove(0);",
        '        let _ = Regex::new("abc");',
        "    }",
        "}",
      ].join("\n"),
    );

    const report = scanRepo(tmp);
    const rules = new Set(report.findings.map((f) => f.rule));
    assert.ok(rules.has("perf-quadratic-loop-scan"));
    assert.ok(rules.has("perf-nplus1-io-in-loop"));
    assert.ok(rules.has("perf-loop-compile-or-deepcopy"));
    assert.ok(rules.has("perf-anti-cheat"));
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test("diff-cheats catches newly added gc.disable() benchmark tampering", () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "vstack-perf-diff-"));
  try {
    spawnSync("git", ["init", "-q"], { cwd: tmp });
    spawnSync("git", ["config", "user.email", "ci@test.local"], { cwd: tmp });
    spawnSync("git", ["config", "user.name", "CI"], { cwd: tmp });
    fs.writeFileSync(path.join(tmp, "bench.py"), "def run():\n    return 1\n");
    spawnSync("git", ["add", "."], { cwd: tmp });
    spawnSync("git", ["commit", "-q", "-m", "init"], { cwd: tmp });

    fs.writeFileSync(path.join(tmp, "bench.py"), "import gc\ndef run():\n    gc.disable()\n    return 1\n");
    const hits = scanGitDiffCheats(tmp, "HEAD");
    assert.ok(hits.some((h) => h.rule === "diff-perf-benchmark-tampering"));
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test("V42 empirical Big-O OLS regression distinguishes O(n) from O(n^2) deterministically and works via CLI", () => {
  const linear = fitEmpiricalBigO(
    [
      { n: 1000, timeMs: 1.0, memoryBytes: 8_000 },
      { n: 2000, timeMs: 2.02, memoryBytes: 16_000 },
      { n: 4000, timeMs: 4.05, memoryBytes: 32_000 },
      { n: 8000, timeMs: 8.1, memoryBytes: 64_000 },
    ],
    { maxTimeExponent: 1.35, maxSpaceExponent: 1.15 },
  );
  assert.equal(linear.passed, true);
  assert.equal(linear.timeClass, "O(n)");
  assert.equal(linear.spaceClass, "O(n)");

  const quadratic = fitEmpiricalBigO(
    [
      { n: 1000, timeMs: 1.0 },
      { n: 2000, timeMs: 4.0 },
      { n: 4000, timeMs: 16.1 },
      { n: 8000, timeMs: 64.5 },
    ],
    { maxTimeExponent: 1.35 },
  );
  assert.equal(quadratic.passed, false);
  assert.equal(quadratic.timeClass, "O(n^2)");

  const liveFast = measureEmpiricalBigO(
    (n, trial) => Array.from({ length: n }, (_, i) => (i + trial) % Math.max(1, Math.floor(n / 2))),
    (arr) => new Set(arr).size,
    [2000, 4000, 8000, 16000],
    { repeats: 5, maxTimeExponent: 1.5 },
  );
  assert.equal(liveFast.result.passed, true);

  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "vstack-bigo-cli-"));
  try {
    const file = path.join(tmp, "scaling.json");
    fs.writeFileSync(
      file,
      JSON.stringify({
        samples: [
          { n: 1000, timeMs: 1 },
          { n: 2000, timeMs: 4 },
          { n: 4000, timeMs: 16 },
          { n: 8000, timeMs: 64 },
        ],
      }),
    );
    const res = spawnSync(
      process.execPath,
      [cliPath, "big-o", file, "--max-time-exp", "1.35", "--json", "--fail"],
      { encoding: "utf8" },
    );
    assert.equal(res.status, 1);
    const parsed = JSON.parse(res.stdout) as { passed: boolean; timeClass: string };
    assert.equal(parsed.passed, false);
    assert.equal(parsed.timeClass, "O(n^2)");
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test("perf-architecture-advisor 90/10 circuit short-circuits static smells and linear code, and guards quadratic contradictions", async () => {
  const inputs: PerfAdvisorInput[] = [
    { file: "src/nplus1.ts", lines: 40, snippet: "for (...) { await fetch(...); }", staticPerfHits: ["perf-nplus1-io-in-loop"] },
    { file: "src/linear.ts", lines: 30, snippet: "new Set(xs)", staticPerfHits: [], timeExponent: 1.02, spaceExponent: 1.0 },
    { file: "src/spatial.ts", lines: 60, snippet: "for (...) { for (...) { dist(a, b); } }", staticPerfHits: [], timeExponent: 2.01 },
    { file: "src/contradict.ts", lines: 50, snippet: "nested()", staticPerfHits: [], timeExponent: 1.98 },
  ];

  const calledIds: string[] = [];
  const engine: System1DecisionEngine = {
    name: "byo-perf-s1",
    async decide(requests) {
      for (const r of requests) calledIds.push(r.id);
      return requests.map((r) => {
        if (r.id.endsWith("pa-003")) {
          return { id: r.id, choice: "algorithmic_complexity", confidence: 0.91, abstained: false };
        }
        return { id: r.id, choice: "no_change_needed", confidence: 0.94, abstained: false };
      });
    },
  };

  const report = await runCircuit(perfArchitectureAdvisorCircuit, inputs, engine);
  assert.equal(report.shortCircuitedCount, 2);
  assert.equal(report.modelCalledCount, 2);
  assert.deepEqual(calledIds, ["perf-architecture-advisor:pa-003", "perf-architecture-advisor:pa-004"]);
  assert.equal(report.receipts[0]?.action, "fix_static_perf_smell");
  assert.equal(report.receipts[1]?.action, "keep_verified");
  assert.equal(report.receipts[2]?.action, "propose_algorithmic_complexity");
  assert.equal(report.receipts[2]?.band, "high");
  assert.equal(report.receipts[3]?.band, "contradicted");
  assert.equal(report.receipts[3]?.requiresHuman, true);
});
