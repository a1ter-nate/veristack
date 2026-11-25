const DIRECTIVE =
  /^(?:eslint-(?:disable|enable)|oxlint-(?:disable|enable)|oxc-|prettier-ignore|biome-ignore|istanbul\s+ignore|c8\s+ignore|v8\s+ignore|node:coverage|@ts-(?:expect-error|ignore|nocheck|check)|<reference\b|nosonar|codeql|@__PURE__|@__NO_SIDE_EFFECTS__)/i;

const LEGAL =
  /\b(?:spdx-license-identifier:|copyright\b|licensed under\b|@license\b|all rights reserved\b)/i;

const GENERATED =
  /<(?:auto-)?generated\b|auto-generated|generated code|\bdo not (?:manually )?edit\b/i;

function normalizeBody(raw) {
  return raw
    .replace(/^\s*\*+\s?/gm, "")
    .replace(/^\s*\/+/gm, "")
    .trim();
}

function isAllowedPrefix(inner, allowPrefixes) {
  return allowPrefixes.some((prefix) => {
    const upper = String(prefix).trim().toUpperCase();
    return upper.length > 0 && inner.toUpperCase().startsWith(`${upper}:`);
  });
}

function isExportedTsDoc(comment, sourceCode) {
  if (comment.type !== "Block" || !comment.value.startsWith("*")) return false;
  const nextToken = sourceCode.getTokenAfter(comment);
  if (!nextToken) return false;
  return nextToken.value === "export";
}

const noCommentsRule = {
  meta: {
    type: "problem",
    docs: {
      description:
        "Disallow prose and excuse comments. Allow tool directives, license/generated headers, exported TSDoc, and configured prefixes (WARNING:, SAFETY:).",
    },
    schema: [
      {
        type: "object",
        properties: {
          allow: {
            type: "array",
            items: { type: "string" },
          },
          allowExportedTsDoc: { type: "boolean" },
        },
        additionalProperties: false,
      },
    ],
    messages: {
      disallowed:
        "Prose comment disallowed. Delete tautology/excuse comments, express intent in names/types, move decisions to ADRs, or prefix real footguns with {{prefixes}}.",
    },
  },
  create(context) {
    const options = context.options[0] ?? {};
    const allowPrefixes = Array.isArray(options.allow) ? options.allow : ["WARNING", "SAFETY"];
    const allowExportedTsDoc = options.allowExportedTsDoc ?? true;
    const sourceCode = context.sourceCode ?? context.getSourceCode();

    return {
      Program() {
        const comments = sourceCode.getAllComments();
        if (comments.length === 0) return;

        const firstToken = sourceCode.getFirstToken(sourceCode.ast);
        const firstCodeLine = firstToken ? firstToken.loc.start.line : Number.MAX_SAFE_INTEGER;
        const hasGeneratedHeader = comments.some(
          (c) => c.loc.start.line < firstCodeLine && GENERATED.test(normalizeBody(c.value)),
        );
        if (hasGeneratedHeader) return;

        const prefixList = allowPrefixes.map((p) => `${String(p).toUpperCase()}:`).join(", ");

        for (const comment of comments) {
          const inner = normalizeBody(comment.value);
          if (!inner) continue;
          const isHeader = comment.loc.start.line < firstCodeLine;
          if (DIRECTIVE.test(inner)) continue;
          if (isHeader && (LEGAL.test(inner) || GENERATED.test(inner))) continue;
          if (isAllowedPrefix(inner, allowPrefixes)) continue;
          if (allowExportedTsDoc && isExportedTsDoc(comment, sourceCode)) continue;

          context.report({
            loc: comment.loc,
            messageId: "disallowed",
            data: { prefixes: prefixList || "WARNING:, SAFETY:" },
          });
        }
      },
    };
  },
};

export default {
  meta: {
    name: "verification-stack",
  },
  rules: {
    "no-comments": noCommentsRule,
  },
};
