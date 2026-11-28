import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { test } from "node:test";
import { scanRepo } from "@veristack/core";

test("Yuan Aspirator, Parse-Don't-Validate, IO-in-TX, backsliding lock, and competing paved-paths catch real violations with zero clean FPs", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "vstack-cs-w1-"));
  try {
    fs.mkdirSync(path.join(dir, "src"), { recursive: true });
    fs.writeFileSync(
      path.join(dir, ".vstack.json"),
      JSON.stringify({
        forbidNewImports: ["legacy-http"],
        retiring: [{ module: "moment", replacement: "date-fns", allowedImporters: ["src/legacy-ok.ts"] }],
      }),
    );
    fs.writeFileSync(
      path.join(dir, "src", "bad.ts"),
      [
        'import oldHttp from "legacy-http";',
        'import moment from "moment";',
        'import axios from "axios";',
        'import got from "got";',
        "export class Store {",
        "  count = 0;",
        "  async write(db: { transaction: (fn: () => Promise<void>) => Promise<void> }): Promise<void> {",
        "    try {",
        "      this.count += 1;",
        "    } catch (err) {",
        "      // TODO handle error",
        "      console.error(err);",
        "    }",
        "    try { this.count += 1; } catch (e) { if (e instanceof TypeError) return; }",
        "    await db.transaction(async () => { await fetch('https://api.example.com/pay'); });",
        "  }",
        "}",
        "export function validateEmail(raw: string): boolean {",
        "  return typeof raw === 'string' && raw.length > 3 && /@/.test(raw);",
        "}",
        "export const keep = [oldHttp, moment, axios, got];",
      ].join("\n"),
    );
    fs.writeFileSync(path.join(dir, "src", "legacy-ok.ts"), 'import moment from "moment";\nexport const ok = moment;\n');
    fs.writeFileSync(
      path.join(dir, "src", "clean.ts"),
      [
        'import axios from "axios";',
        "export function parseEmail(raw: string): { readonly email: string } {",
        "  if (typeof raw !== 'string' || !raw.includes('@')) throw new Error('invalid');",
        "  return { email: raw };",
        "}",
        "export const http = axios;",
      ].join("\n"),
    );
    const report = scanRepo(dir);
    const badRules = new Set(report.findings.filter((f) => f.file === "src/bad.ts").map((f) => f.rule));
    assert.equal(badRules.has("aspirator-todo-in-error-path"), true);
    assert.equal(badRules.has("aspirator-log-and-continue-mutation"), true);
    assert.equal(badRules.has("aspirator-overbroad-invariant-catch"), true);
    assert.equal(badRules.has("io-inside-db-transaction"), true);
    assert.equal(badRules.has("validate-and-discard"), true);
    assert.equal(badRules.has("backsliding-forbidden-import"), true);
    assert.equal(badRules.has("competing-paved-paths"), true);
    assert.equal(report.findings.some((f) => f.file === "src/legacy-ok.ts" && f.rule === "backsliding-forbidden-import"), false);
    assert.equal(report.findings.some((f) => f.file === "src/clean.ts" && f.rule === "validate-and-discard"), false);
    assert.equal(report.findings.some((f) => f.file === "src/clean.ts" && f.rule === "competing-paved-paths"), false);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("Liskov behavioral subtyping catches unimplemented overrides and widened return types across TS, C#, Rust, and Python", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "vstack-liskov-"));
  try {
    fs.mkdirSync(path.join(dir, "src"), { recursive: true });
    fs.writeFileSync(
      path.join(dir, "src", "port.ts"),
      [
        "export interface RepoPort { load(id: string): string; save(v: string): void; }",
        "export class BrokenRepo implements RepoPort {",
        "  load(id: string): string | null { return id ? id : null; }",
        "  save(_v: string): void { throw new NotImplementedError('readonly'); }",
        "}",
        "export class CleanRepo implements RepoPort {",
        "  load(id: string): string { return id; }",
        "  save(_v: string): void { return; }",
        "}",
      ].join("\n"),
    );
    fs.writeFileSync(
      path.join(dir, "src", "Adapter.cs"),
      "public class BadAdapter : IRepo { public void Save() { throw new NotImplementedException(); } }\n",
    );
    fs.writeFileSync(
      path.join(dir, "src", "adapter.rs"),
      "impl Storage for MemStore { fn flush(&self) { todo!() } }\n",
    );
    fs.writeFileSync(
      path.join(dir, "src", "adapter.py"),
      "class BadStore(BaseStore):\n    def save(self, x):\n        raise NotImplementedError()\n",
    );
    const report = scanRepo(dir);
    assert.equal(report.findings.some((f) => f.file === "src/port.ts" && f.rule === "liskov-unimplemented-override"), true);
    assert.equal(report.findings.some((f) => f.file === "src/port.ts" && f.rule === "liskov-widened-return-type"), true);
    assert.equal(report.findings.some((f) => f.file === "src/Adapter.cs" && f.rule === "liskov-unimplemented-override"), true);
    assert.equal(report.findings.some((f) => f.file === "src/adapter.rs" && f.rule === "liskov-unimplemented-override"), true);
    assert.equal(report.findings.some((f) => f.file === "src/adapter.py" && f.rule === "liskov-unimplemented-override"), true);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
