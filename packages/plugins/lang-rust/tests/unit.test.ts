import assert from "node:assert/strict";
import { test } from "node:test";
import { createPluginHostSync, scanRepo } from "@veristack/core";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { isVeristackPlugin } from "@veristack/plugin";
import { langRustPlugin } from "@veristack/plugin-lang-rust";

test("lang-rust plugin defines valid Veristack plugin and registers into languages", () => {
  assert.equal(isVeristackPlugin(langRustPlugin), true);
  assert.equal(langRustPlugin.id, "veristack.plugin.lang-rust");
  const host = createPluginHostSync({ includeBuiltins: false, plugins: [langRustPlugin] });
  const statuses = host.list();
  assert.equal(statuses.length, 1);
  assert.equal(statuses[0]?.status, "active");
  assert.ok(host.registries.languages().length >= 1);
});

test("Rust rules ignore multi-arg key unwrap, clippy expect with reason, UNIX_EPOCH timestamps, try_into_mut, and cfg(test) modules", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "vstack-rust-fp-"));
  try {
    fs.mkdirSync(path.join(dir, "src"), { recursive: true });
    fs.writeFileSync(
      path.join(dir, "src", "clean.rs"),
      [
        "use std::time::{SystemTime, UNIX_EPOCH};",
        "pub fn clean_ops(kek: &Kek, enc: &[u8], out: &mut [u8], b: Bytes) -> u64 {",
        "    let _ = kek.unwrap(enc, out);",
        '    #[expect(clippy::expect_used, reason = "compile-time constant regex")]',
        '    let _n = Some(1).expect("const");',
        "    let secs = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);",
        "    match b.try_into_mut() { Ok(mut m) => { m.clear(); } Err(_) => {} }",
        "    secs",
        "}",
      ].join("\n"),
    );
    fs.writeFileSync(
      path.join(dir, "src", "properties.rs"),
      "#![cfg(test)]\npub fn helper() -> usize { Some(1).unwrap() }\n",
    );
    const report = scanRepo(dir);
    const rules = new Set(report.findings.map((f) => f.rule));
    assert.equal(rules.has("rust-prod-unwrap-or-expect"), false);
    assert.equal(rules.has("cdc-wall-clock-duration"), false);
    assert.equal(rules.has("no-swallowing-catch"), false);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
