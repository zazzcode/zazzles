# Code injection

[Analysis rules](README.md) · [Open redirect](open-redirect.md) · [Next.js](nextjs.md)

The `code` family asks whether request-derived text reaches the code operand of a verified
interpreter API. It uses `code_execution_candidate`, protocol `code-components-v1`, and CWE-94/95.
Browser eval is a code-injection claim with browser execution context; it does not produce a duplicate
XSS claim.

## Verified operations

- JavaScript global `eval`, including indirect eval, and `Function` / `new Function`. Every Function
  argument is code, including parameter declarations. Shadowed or reassigned globals are excluded.
- Browser string timers (`setTimeout`, `setInterval`, `setImmediate`); function callbacks are excluded.
  Node timers are not string evaluators.
- Imported Node `vm` execution/compilation APIs. The code string is the operand; request data passed
  only in a context object creates no code claim. Node explicitly says [vm is not a security
  mechanism](https://nodejs.org/api/vm.html).
- Verified evaluator imports from notevil, safe-eval, static-eval, mathjs and expr-eval, and immutable
  VM/NodeVM or Parser instances. Library isolation remains Review without an established advisory.
  notevil carries [CVE-2021-23771](https://github.com/advisories/GHSA-8g4m-cjm2-96wq), a sandbox
  escape affecting all published versions, and is poor practice.
- Python unshadowed `eval`, `exec`, and `compile`; `ast.literal_eval` is excluded. Flask and the
  other supported Python HTTP adapters reuse their existing request acquisition.

## Evidence and decisions

Each operand has source paths, verified binding evidence, callable/control-flow evidence, and its
own guards. Quoting request text inside executable JavaScript does not remove code injection: a
quote break-out remains possible. Numeric conversion is established only when the *entire operand*
is constrained. `eval(Number(q) + q)` retains a raw occurrence. `JSON.stringify` as the complete code
operand produces a literal; placing its output inside another quoted code string is a different
context and receives no such guarantee.

Questions separate code position (`whole_program`, `inside_string_literal`, `data_only`, `none`,
`unknown`), restriction (`allowlist_grammar`, `type_conversion`, `blacklist_only`, `sandbox_library`,
`none`, `unknown`) and protection coverage. A raw complete path with no effective restriction supports
Confirmed. Complete enforcing grammar/conversion coverage supports Protected. Blacklists, type
annotations, exception handlers and sandbox branding do not establish protection. Inconsistent
answers, unresolved relevant transfers and missing bindings remain Review.

## Bounds

This is bounded source analysis, without runtime execution. Arbitrary dynamic aliases, monkey
patches, sandbox object factories and unmodeled control flow remain unresolved. Template injection,
deserialization, module loading and WebAssembly are separate concerns. Server-to-client props are
followed one imported component hop; deeper component chains and state transitions remain bounded.

A Sequelize stored value read by `findByPk`/finders can link back to its request writer
(`user.update({field: req.body.field})`) for a code operand, reusing the stored-XSS write/read link.
A model setter that only sanitizes HTML is a transfer, not a code restriction. Seed-only writers and
other columns remain unresolved. A browser `eval` records only the code claim; string timers and
`Function` keep their separate script-context XSS records.

Use `--only-family code` with a judged scan to select this family. Offline evidence and practice
observations do not consume model requests.
