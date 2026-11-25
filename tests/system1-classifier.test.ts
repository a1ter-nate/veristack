import assert from "node:assert/strict";
import fs from "node:fs";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { buildSystem1Packet, corroborateSystem1Batch } from "../src/system1-classifier.ts";
import { runSystem1Provider } from "../src/system1-providers.ts";

test("System 1 classifier balances components, emits requests, and refuses to let a model override static facts", () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "vstack-s1-"));
  try {
    fs.mkdirSync(path.join(tmp, "apps", "web", "tests"), { recursive: true });
    fs.mkdirSync(path.join(tmp, "apps", "api", "tests"), { recursive: true });
    fs.writeFileSync(
      path.join(tmp, "apps", "web", "tests", "coverage-leftovers.test.ts"),
      "import { test, expect } from 'vitest';\ntest('taut', () => { expect(1).toBe(1); });\n",
    );
    fs.writeFileSync(
      path.join(tmp, "apps", "api", "tests", "pricing.test.ts"),
      "import { test, expect } from 'vitest';\nimport { price } from '../src/pricing';\ntest('p', () => { expect(price(10)).toBe(12); });\n",
    );
    fs.writeFileSync(path.join(tmp, "AGENTS.md"), "Never use Date.now in tests.\n");

    const packet = buildSystem1Packet(tmp, { maxCandidates: 10 });
    assert.equal(packet.selectedCount, 3);
    assert.equal(packet.componentDistribution.length, 3);

    const farmReq = packet.requests.find((r) => r.rubricId === "test-value" && r.snippet.includes("expect(1).toBe(1)"));
    assert.ok(farmReq);

    const disagreed = corroborateSystem1Batch(packet, [
      { id: farmReq.id, choice: "BEHAVIOR", confidence: 0.99, abstained: false },
    ]);
    const farmJudgment = disagreed.judgments.find(
      (j) => j.candidateId === farmReq.candidateId && j.rubricId === "test-value",
    );
    assert.equal(farmJudgment?.verdict, "disagreed_human_review");

    const corroborated = corroborateSystem1Batch(packet, [
      { id: farmReq.id, choice: "COVERAGE_FARM", confidence: 0.91, abstained: false },
    ]);
    const farmOk = corroborated.judgments.find(
      (j) => j.candidateId === farmReq.candidateId && j.rubricId === "test-value",
    );
    assert.equal(farmOk?.verdict, "corroborated_issue");
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test("System 1 provider adapters execute real HTTP against local OpenAI-compat and JEV endpoints and block live runs under test guard", async () => {
  const sampleReq = [
    {
      id: "s1-001:test-value",
      candidateId: "s1-001",
      rubricId: "test-value" as const,
      question: "Value?",
      choices: ["BEHAVIOR", "TAUTOLOGY"],
      factContext: "context=complete",
      snippet: "expect(1).toBe(1)",
    },
  ];

  await assert.rejects(
    () => runSystem1Provider(sampleReq, { provider: "local", env: { VSTACK_NO_LIVE_INFERENCE: "1" } }),
    /blocked under test mode/,
  );

  const fixtureAnswers = await runSystem1Provider(sampleReq, { provider: "fixture", env: { NODE_ENV: "test" } });
  assert.equal(fixtureAnswers[0]?.choice, "BEHAVIOR");

  const server = http.createServer((req, res) => {
    let body = "";
    req.on("data", (chunk) => {
      body += chunk;
    });
    req.on("end", () => {
      if (req.url === "/jev") {
        const parsed = JSON.parse(body);
        res.writeHead(200, { "content-type": "application/json" });
        res.end(
          JSON.stringify({
            results: parsed.requests.map((r: { id: string }) => ({
              id: r.id,
              choice: "TAUTOLOGY",
              confidence: 0.93,
              abstained: false,
            })),
          }),
        );
        return;
      }
      res.writeHead(200, { "content-type": "application/json" });
      res.end(
        JSON.stringify({
          choices: [{ message: { content: JSON.stringify({ choice: "TAUTOLOGY", confidence: 0.88, abstained: false }) } }],
        }),
      );
    });
  });

  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  assert.ok(address && typeof address === "object");
  const baseUrl = `http://127.0.0.1:${address.port}`;

  try {
    const devEnv = { NODE_ENV: "development" };
    const jevOut = await runSystem1Provider(sampleReq, { provider: "jev", endpoint: `${baseUrl}/jev`, env: devEnv });
    assert.equal(jevOut[0]?.choice, "TAUTOLOGY");
    assert.equal(jevOut[0]?.confidence, 0.93);

    const localOut = await runSystem1Provider(sampleReq, {
      provider: "local",
      endpoint: `${baseUrl}/v1/chat/completions`,
      model: "qwen3.5:9b",
      env: devEnv,
    });
    assert.equal(localOut[0]?.choice, "TAUTOLOGY");
    assert.equal(localOut[0]?.confidence, 0.88);
  } finally {
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }
});
