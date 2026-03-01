module.exports = {
  root: true,
  env: {
    browser: true,
    es2021: true,
    node: true,
  },
  parserOptions: {
    ecmaVersion: "latest",
    sourceType: "module",
  },
  rules: {
    "no-eval": "error",
    "no-implied-eval": "error",
    "no-unused-vars": ["warn", { argsIgnorePattern: "^_" }],
    "no-console": "warn",
    "eqeqeq": "error",
  },
};
