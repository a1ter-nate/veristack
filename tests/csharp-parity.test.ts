import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { scanGitDiffCheats } from "../src/ci-auditor.ts";
import type { ScannedFile } from "../src/discover.ts";
import { scanRepo } from "../src/ladder.ts";
import { lintNoComments } from "../src/no-comments.ts";
import { lintImplicitStateMachinesInFile } from "../src/state-machines/index.ts";
import { buildSystem1Packet } from "../src/system1-classifier.ts";

function fakeCs(rel: string, content: string): ScannedFile {
  return {
    rel,
    abs: `/virtual/${rel}`,
    language: "csharp",
    isTest: false,
    isWorkflow: false,
    content,
    lines: content.split(/\r?\n/).length,
  };
}

test("C# state-machine scanner catches all 4 implicit state machine patterns (red) and passes explicit record hierarchy (green)", () => {
  const badSoup = `public sealed class Sim { public bool IsRunning { get; set; } public bool IsArmed { get; set; } }`;
  assert.deepEqual(
    lintImplicitStateMachinesInFile(fakeCs("src/Sim.cs", badSoup)).map((f) => f.rule),
    ["implicit-sm-boolean-soup"],
  );

  const badBag = `public sealed record RunDto(RunStatus Status, string? Error, long? FinishedAt);`;
  assert.deepEqual(
    lintImplicitStateMachinesInFile(fakeCs("src/RunDto.cs", badBag)).map((f) => f.rule),
    ["implicit-sm-optional-bag"],
  );

  const badScattered = [
    "public sealed class Job {",
    "  public JobStatus Status { get; private set; }",
    "  public void Start() { Status = JobStatus.Running; }",
    "  public void Stop() { Status = JobStatus.Stopped; }",
    "}",
  ].join("\n");
  assert.deepEqual(
    lintImplicitStateMachinesInFile(fakeCs("src/Job.cs", badScattered)).map((f) => f.rule),
    ["implicit-sm-scattered-mutation"],
  );

  const badSwitchExpr = [
    "public static class L {",
    "  public static string Name(OrderState state) => state switch {",
    '    OrderState.Pending => "p",',
    '    OrderState.Shipped => "s",',
    "  };",
    "}",
  ].join("\n");
  assert.deepEqual(
    lintImplicitStateMachinesInFile(fakeCs("src/L.cs", badSwitchExpr)).map((f) => f.rule),
    ["implicit-sm-non-exhaustive-switch"],
  );

  const goodExplicit = [
    "public abstract record OrderState {",
    "  private OrderState() { }",
    "  public sealed record Pending(int Amount) : OrderState;",
    "  public sealed record Shipped(int Amount, string Tracking) : OrderState;",
    "}",
    "public sealed record RunnerOptions(RunMode Mode, bool EnableCache, bool Verbose, string? Endpoint, int? TimeoutMs);",
    "public static class Machine {",
    "  public static string Name(OrderState state) => state switch {",
    '    OrderState.Pending => "p",',
    '    OrderState.Shipped => "s",',
    "    _ => throw new UnreachableException(),",
    "  };",
    "}",
  ].join("\n");
  assert.deepEqual(lintImplicitStateMachinesInFile(fakeCs("src/Good.cs", goodExplicit)), []);
});

test("C# no-comments allows public XML doc comments and tags while rejecting prose and private XML docs", () => {
  const src = [
    "// SPDX-License-Identifier: MIT",
    "/// <summary>Public API.</summary>",
    "public sealed class Demo {",
    "  // WARNING: hardware buffer is 64 bytes",
    "  public int Calc() { return 1; }",
    "  // excuse comment",
    "  private int Helper() { return 2; }",
    "}",
  ].join("\n");
  const hits = lintNoComments("src/Demo.cs", src, "csharp");
  assert.equal(hits.length, 1);
  assert.equal(hits[0]?.line, 6);
});

test("C# structure & anti-cheat scanner catches ForTesting seams, dynamic, empty catch, pragma, SuppressMessage, and csproj cheats", () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "vstack-cs-"));
  try {
    fs.writeFileSync(
      path.join(tmp, "App.csproj"),
      "<Project><PropertyGroup><TreatWarningsAsErrors>false</TreatWarningsAsErrors><NoWarn>CS0168</NoWarn></PropertyGroup></Project>\n",
    );
    fs.writeFileSync(
      path.join(tmp, "Service.cs"),
      [
        "using System.Diagnostics.CodeAnalysis;",
        "public sealed class Service {",
        '  [SuppressMessage("Design", "CA1031")]',
        "  public int ResetForTesting(dynamic payload) {",
        "#pragma warning disable CS0168",
        "    try { return 1; } catch (Exception) { }",
        "    return 0;",
        "  }",
        "}",
      ].join("\n"),
    );

    const report = scanRepo(tmp);
    const rules = new Set(report.findings.map((f) => f.rule));
    assert.ok(rules.has("csproj-warnings-not-errors"));
    assert.ok(rules.has("csproj-nowarn-suppression"));
    assert.ok(rules.has("no-test-only-production-seam"));
    assert.ok(rules.has("no-chained-or-any-cast"));
    assert.ok(rules.has("no-swallowing-catch"));
    assert.ok(rules.has("suppression-audit"));
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test("diff-cheats catches newly added C# Skip, TreatWarningsAsErrors=false, NoWarn, pragma disable, and dotnet test || true", () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "vstack-cs-diff-"));
  try {
    spawnSync("git", ["init", "-q"], { cwd: tmp });
    spawnSync("git", ["config", "user.email", "ci@test.local"], { cwd: tmp });
    spawnSync("git", ["config", "user.name", "CI"], { cwd: tmp });
    fs.writeFileSync(path.join(tmp, "App.csproj"), "<Project><PropertyGroup><TreatWarningsAsErrors>true</TreatWarningsAsErrors></PropertyGroup></Project>\n");
    fs.writeFileSync(path.join(tmp, "Tests.cs"), "public class T { [Fact] public void Ok() { } }\n");
    fs.writeFileSync(path.join(tmp, "ci.sh"), "dotnet test\n");
    spawnSync("git", ["add", "."], { cwd: tmp });
    spawnSync("git", ["commit", "-q", "-m", "init"], { cwd: tmp });

    fs.writeFileSync(
      path.join(tmp, "App.csproj"),
      "<Project><PropertyGroup><TreatWarningsAsErrors>false</TreatWarningsAsErrors><NoWarn>VSTACK002</NoWarn></PropertyGroup></Project>\n",
    );
    fs.writeFileSync(
      path.join(tmp, "Tests.cs"),
      'public class T {\n#pragma warning disable CS0168\n[Fact(Skip = "flaky")] public void Ok() { }\n}\n',
    );
    fs.writeFileSync(path.join(tmp, "ci.sh"), "dotnet test || true\n");

    const hits = scanGitDiffCheats(tmp, "HEAD");
    const rules = new Set(hits.map((h) => h.rule));
    assert.ok(rules.has("diff-csproj-warnings-not-errors"));
    assert.ok(rules.has("diff-csproj-nowarn"));
    assert.ok(rules.has("diff-csharp-skipped-test"));
    assert.ok(rules.has("diff-csharp-pragma-disable"));
    assert.ok(rules.has("diff-swallowed-failure"));
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test("C# test-analyzer catches nondeterminism, env mutation, stopwatch timing, self-derived assert, multi-status assert, and unexercised test", () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "vstack-cs-tests-"));
  try {
    fs.writeFileSync(
      path.join(tmp, "BadTests.cs"),
      [
        "using System;",
        "using System.Diagnostics;",
        "using System.Net;",
        "using Xunit;",
        "public sealed class BadTests {",
        "  [Fact]",
        "  public void Smells() {",
        '    Environment.SetEnvironmentVariable("K", "V");',
        "    var now = DateTime.UtcNow;",
        "    var rng = new Random();",
        "    var sw = Stopwatch.StartNew();",
        "    Assert.True(sw.ElapsedMilliseconds < 50);",
        "    Assert.Equal(Calc(2), Calc(2));",
        "    Assert.Contains(status, new[] { HttpStatusCode.OK, HttpStatusCode.NotFound });",
        "  }",
        "  private static int Calc(int x) => x + 1;",
        "}",
      ].join("\n"),
    );

    const report = scanRepo(tmp);
    const rules = new Set(report.findings.map((f) => f.rule));
    assert.ok(rules.has("no-unexercised-test"));
    assert.ok(rules.has("no-imported-mutation"));
    assert.ok(rules.has("no-test-nondeterminism"));
    assert.ok(rules.has("no-elapsed-time-bound"));
    assert.ok(rules.has("self-derived-expectation"));
    assert.ok(rules.has("no-multi-status-assertion"));
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test("System 1 classifier extracts C# SUT imports and classifies templates/csharp-reference as BEHAVIOR", () => {
  const csharpRef = path.resolve(import.meta.dir, "..", "templates", "csharp-reference");
  const report = buildSystem1Packet(csharpRef, { maxCandidates: 10 });
  assert.ok(report.candidates.length >= 3);
  const transitionCand = report.candidates.find((c) => c.file.endsWith("TransitionTableTests.cs"));
  assert.ok(transitionCand);
  assert.equal(transitionCand.hasSutImport, true);
  const propCand = report.candidates.find((c) => c.file.endsWith("OrderPropertyTests.cs"));
  assert.ok(propCand);
  assert.equal(propCand.hasSutImport, true);
  const propJudgment = report.judgments.find(
    (j) => j.candidateId === propCand.id && j.rubricId === "test-value",
  );
  assert.ok(propJudgment);
  assert.equal(propJudgment.staticLabel, "BEHAVIOR");
});
