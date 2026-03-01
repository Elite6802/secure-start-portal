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
    ecmaFeatures: { jsx: true },
  },
  plugins: ["react"],
  rules: {
    "react/jsx-no-target-blank": "error",
    "react/jsx-key": "error",
    "react/no-unknown-property": "error",
    "no-unused-vars": ["warn", { argsIgnorePattern: "^_" }],
  },
  settings: {
    react: { version: "detect" },
  },
};
