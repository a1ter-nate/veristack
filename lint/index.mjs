import noCommentsPlugin from "./oxlint-no-comments.mjs";
import explicitStateMachinePlugin from "./oxlint-explicit-state-machine.mjs";

const reflectRule = {
  meta: {
    type: "problem",
    docs: { description: "Disallow dynamic Reflect.apply/get/set bypasses." },
    schema: [],
  },
  create(context) {
    return {
      CallExpression(node) {
        const callee = node.callee;
        if (
          callee &&
          callee.type === "MemberExpression" &&
          callee.object?.type === "Identifier" &&
          callee.object.name === "Reflect" &&
          callee.property?.type === "Identifier" &&
          (callee.property.name === "apply" || callee.property.name === "get" || callee.property.name === "set")
        ) {
          context.report({
            node,
            message: `Avoid Reflect.${callee.property.name}(); use direct typed calls or explicit property access.`,
          });
        }
      },
    };
  },
};

const unknownAliasRule = {
  meta: {
    type: "suggestion",
    docs: { description: "Disallow type aliases to unknown or any." },
    schema: [],
  },
  create(context) {
    return {
      TSTypeAliasDeclaration(node) {
        const ann = node.typeAnnotation;
        if (ann && (ann.type === "TSUnknownKeyword" || ann.type === "TSAnyKeyword")) {
          context.report({
            node,
            message: `Type alias '${node.id?.name ?? "alias"}' hides '${ann.type === "TSAnyKeyword" ? "any" : "unknown"}'; define a real contract type.`,
          });
        }
      },
    };
  },
};

const unsafeDictRule = {
  meta: {
    type: "suggestion",
    docs: { description: "Disallow Record<string, any> and boxed Object/Function types." },
    schema: [],
  },
  create(context) {
    return {
      TSTypeReference(node) {
        const name = node.typeName?.type === "Identifier" ? node.typeName.name : "";
        if (name === "Object" || name === "Function") {
          context.report({
            node,
            message: `Avoid boxed '${name}' type; declare an explicit interface or callable signature.`,
          });
          return;
        }
        const params = node.typeArguments?.params ?? node.typeParameters?.params;
        if (name === "Record" && Array.isArray(params) && params[1]?.type === "TSAnyKeyword") {
          context.report({
            node,
            message: "Avoid Record<string, any>; use an explicit interface, Map, or Record<K, unknown> parsed at the boundary.",
          });
        }
      },
    };
  },
};

export default {
  meta: { name: "veristack" },
  rules: {
    ...noCommentsPlugin.rules,
    ...explicitStateMachinePlugin.rules,
    "no-reflect-dynamic-invoke": reflectRule,
    "no-unknown-type-alias": unknownAliasRule,
    "no-unsafe-dictionary-type": unsafeDictRule,
  },
};
