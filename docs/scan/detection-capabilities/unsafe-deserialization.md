# Unsafe deserialization

[Detection capabilities](../detection-capabilities.md) · [Analysis rules](../analysis/deserialization.md)

The `deserialization` family follows request data to verified object or code-capable deserializers
in Python, server-side JavaScript and TypeScript, and PHP. A judged scan can report
**Unsafe deserialization** ([CWE-502](https://cwe.mitre.org/data/definitions/502.html)).
Use `--only-family deserialization` with `--analyze --judge` to assess this family alone.

| Language | Covered libraries or operations |
| --- | --- |
| Python | Pickle family, PyYAML and jsonpickle |
| JavaScript and TypeScript | node-serialize, funcster and js-yaml |
| PHP | Global `unserialize` and Symfony `Yaml::parse` in PHP entries, controllers, reached services, and Twig globals |

## Recorded and decidable

Symfony service calls reached from route actions and Twig globals retain their request-byte
path and the existing PHP option evidence.

## Recorded in Review

A dynamic class policy or Symfony YAML flag stays unresolved. Supply the option value and its
binding before treating it as a restriction.

Use a data-only format when accepting untrusted bytes. Choose a safe YAML loader or schema,
or parse JSON and validate the resulting fields. For trusted serialized messages, enforce a
keyed integrity check over the same bytes before deserialization.

Results use source-backed bindings and flag, schema or loader facts. Object injection findings
describe the ability to select classes. Their effects depend on which classes are available.

A dependency advisory reports an affected package or version. This source-analysis family establishes that
a supported deserializer receives request data and uses the library version when it determines parser behavior.
