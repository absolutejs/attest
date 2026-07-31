import pluginJs from "@eslint/js";
import stylistic from "@stylistic/eslint-plugin";
import tsParser from "@typescript-eslint/parser";
import { defineConfig } from "eslint/config";
import absolutePlugin from "eslint-plugin-absolute";
import promisePlugin from "eslint-plugin-promise";
import securityPlugin from "eslint-plugin-security";
import globals from "globals";
import tseslint from "typescript-eslint";

export default defineConfig([
  {
    ignores: ["node_modules/**", "dist/**"],
  },
  pluginJs.configs.recommended,
  ...tseslint.configs.recommended,
  {
    files: ["**/*.{ts,tsx}"],
    languageOptions: {
      globals: {
        ...globals.node,
        Buffer: "readonly",
        Bun: "readonly",
        NodeJS: "readonly",
      },
      parser: tsParser,
      parserOptions: {
        project: "./tsconfig.eslint.json",
        tsconfigRootDir: import.meta.dirname,
      },
    },
    plugins: { "@stylistic": stylistic },
    rules: {
      "@stylistic/padding-line-between-statements": [
        "error",
        { blankLine: "always", next: "return", prev: "*" },
      ],
      "@typescript-eslint/consistent-type-assertions": [
        "error",
        { assertionStyle: "never" },
      ],
      "@typescript-eslint/consistent-type-definitions": ["error", "type"],
      "@typescript-eslint/no-non-null-assertion": "error",
      "@typescript-eslint/no-unnecessary-type-assertion": "error",
    },
  },
  {
    files: ["**/*.{js,mjs,cjs,ts,tsx,jsx}"],
    languageOptions: {
      globals: {
        ...globals.browser,
      },
    },
    plugins: {
      absolute: absolutePlugin,
      promise: promisePlugin,
      security: securityPlugin,
    },
    rules: {
      "absolute/explicit-object-types": "error",
      "absolute/min-var-length": [
        "error",
        {
          allowedVars: ["id", "OK"],
          minLength: 3,
        },
      ],
      "absolute/no-explicit-return-type": "error",
      "absolute/no-import-meta-path": "error",
      "absolute/no-useless-function": "error",
      "absolute/sort-exports": [
        "error",
        {
          caseSensitive: true,
          natural: true,
          order: "asc",
          variablesBeforeFunctions: true,
        },
      ],
      "absolute/sort-keys-fixable": [
        "error",
        {
          caseSensitive: true,
          natural: true,
          order: "asc",
          variablesBeforeFunctions: true,
        },
      ],
      "arrow-body-style": ["error", "as-needed"],
      "consistent-return": "error",
      eqeqeq: "error",
      "func-style": ["error", "expression", { allowArrowFunctions: true }],
      "no-await-in-loop": "error",
      "no-debugger": "error",
      "no-duplicate-imports": "error",
      "no-else-return": "error",
      "no-empty-function": "error",
      "no-fallthrough": "error",
      "no-implicit-coercion": "error",
      "no-magic-numbers": [
        "warn",
        { detectObjects: false, enforceConst: true, ignore: [0, 1, 2] },
      ],
      "no-nested-ternary": "error",
      "no-param-reassign": "error",
      "no-restricted-exports": [
        "error",
        { restrictDefaultExports: { direct: true } },
      ],
      "no-return-await": "error",
      "no-shadow": "error",
      "no-undef": "error",
      "no-unneeded-ternary": "error",
      "no-unreachable": "error",
      "no-useless-assignment": "error",
      "no-useless-return": "error",
      "no-var": "error",
      "prefer-arrow-callback": "error",
      "prefer-const": "error",
      "prefer-destructuring": [
        "error",
        { array: true, object: true },
        { enforceForRenamedProperties: false },
      ],
      "prefer-template": "error",
      "promise/always-return": "warn",
      "promise/catch-or-return": "error",
      "promise/no-return-wrap": "error",
      "promise/param-names": "error",
    },
  },
  {
    files: ["eslint.config.mjs"],
    rules: {
      "absolute/no-import-meta-path": "off",
      "no-magic-numbers": "off",
      "no-restricted-exports": "off",
    },
  },
]);
