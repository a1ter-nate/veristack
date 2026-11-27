import { Plugin } from "@veristack/plugin";
import { analyzeEffectV4Rules } from "./effect-rules.ts";

export { analyzeEffectV4Rules };

export const effectV4Plugin = Plugin.define({
  id: "veristack.plugin.effect-v4",
  setup(ctx) {
    ctx.analyzer.transform((ed) => {
      ed.add({
        id: "veristack.effect-v4.rules",
        phase: "lint",
        run: (runCtx) => runCtx.repo.files.flatMap((file) => analyzeEffectV4Rules(file)),
      });
    });
  },
});

export default effectV4Plugin;
