import assert from "node:assert/strict";
import { test } from "node:test";
import { definePlugin, isVeristackPlugin, lineOf, maskCode, Plugin } from "@veristack/plugin";

test("Plugin.define brands valid plugins and rejects empty ids", () => {
  const created = Plugin.define({ id: "sample.unit.plugin", setup() {} });
  assert.equal(isVeristackPlugin(created), true);
  assert.equal(created.id, "sample.unit.plugin");
  assert.throws(() => definePlugin({ id: "   ", setup() {} }));
  assert.equal(lineOf("a\nb\nc", 4), 3);
  assert.equal(maskCode("const s = \"hello\";", "typescript").includes("hello"), false);
});
