# Unsafe deserialization

Zazzles emits a `deserialization_candidate` when a value with a modeled origin reaches the
data operand of a verified deserializer. The analyzer records the binding, option and version
facts, and each source path. A judged scan uses those facts to classify CWE-502.

## Python

| Operation | Capability and option facts |
| --- | --- |
| `pickle`, `_pickle`, `cPickle`, `dill`, `cloudpickle` | `load`, `loads` and `Unpickler(...).load()` support code execution by format design. An in-project subclass's `find_class` method is recorded as a class restriction when present. |
| PyYAML `load` and `load_all` | Unsafe and legacy loaders support code execution. Full loaders have restricted types and stay Review. Safe and base loaders emit no record. The unresolved `Loader` argument stays Review. |
| PyYAML defaults | With the loader omitted, versions before 5.1 support code execution by format design. From 5.1 up to 6.0 the default has restricted types. At 6.0 and later the call requires a loader. An unknown version stays Review. |
| PyYAML named forms | `unsafe_load` and `unsafe_load_all` support code execution by format design. `full_load` and `full_load_all` have restricted types. Safe variants emit no record. |
| `jsonpickle.decode` | Supports code execution by format design, including with `safe=True`. |
| Transfers | String and byte conversions, stream wrappers and reads, base64 family decoding, binascii and hex decoding, zlib/gzip/bz2/lzma decompression and modeled URL decoding retain origin. |
| Controls | A dominating or enclosing check on the operand is recorded. Verified HMAC or signing calls supply integrity evidence, hashlib supplies unkeyed-hash evidence, and a subclass's `find_class` supplies a class-restriction citation. |

The nearest directory containing `requirements*.txt`, `poetry.lock` or `uv.lock` determines the
PyYAML version when an exact pin is present. Conflicting pins and missing pins stay Review.

## JavaScript and TypeScript

| Operation | Capability and option facts |
| --- | --- |
| `node-serialize.unserialize`, `funcster.deepDeserialize` | Support code execution by format design. |
| js-yaml `load` and `loadAll` | The default before 4.0.0 supports code execution by format design. The default starting with 4.0.0 parses plain data. An exact manifest or lockfile version is required. |
| js-yaml explicit schemas | Before 4.0.0, `DEFAULT_FULL_SCHEMA` supports code execution by format design, including on explicit overrides of `safeLoad` and `safeLoadAll`. Known data-only schemas emit no record. Unresolved schemas and versions stay Review. |
| Transfers | `Buffer.from`, `.toString()`, `String`, base64 and URL decoding, Node zlib decompression and TypeScript casts retain origin. |
| Controls | A guard can cite verified Node `crypto` HMAC or timing-safe comparison calls. `crypto.createHash` is unkeyed-hash evidence. |

The adapter uses supported HTTP, Next.js server, GraphQL and unary gRPC input paths.

## PHP

| Operation | Capability and option facts |
| --- | --- |
| Global `unserialize` | Deserialized objects can instantiate data-selected classes. A literal `['allowed_classes' => false]` option suppresses the record. An explicit class list is recorded as a restriction. The scanner cites up to 20 in-project class declarations with supported magic methods or `Serializable` implementations. |
| Symfony `Yaml::parse` | `PARSE_OBJECT` enables object injection. A verified flag set without it emits no record. Unresolved flags stay Review. |
| Transfers | Base64, URL, hex and gzip-family decoding, `stripslashes`, `trim` and string casts retain origin. |
| Controls | A branch can cite a keyed comparison, HMAC or Sodium verification. MD5, SHA-1, `hash` and CRC checks supply unkeyed-hash evidence. A rejecting branch counts when its last statement exits, returns or throws. A test that only checks presence, emptiness, type or the request method (`isset`, `empty`, `is_string`, a comparison with `null`) is not a control, so the path stays raw. |

## Outcomes and limits

An unguarded request path with a verified code-execution or object-injection capability can
become Confirmed. Reporting labels PHP object injection by its own impact. A keyed check must
enforce integrity for the same bytes before deserialization. A class allow-list must adequately
restrict the possible classes. The judge can establish Protected when adequate controls cover
every path. Decoding, format checks and unkeyed hashes alone leave the claim unresolved.

A supported non-request origin without a request witness stays Review. Literal input,
file-only reads, unmodeled sockets and data-only parsing are excluded. Version ranges and type
package versions provide no exact version facts. Browser operations, dynamic callable dispatch,
phar metadata, unspecified libraries and gadget-chain analysis are out of scope. The PHP adapter
uses server-mapped entries. Symfony controller dispatch and service wiring are separate coverage.

Further limits of the supported subset:

- Python: an `Unpickler` subclass with more than one base class, or one that defines its own
  `load`, emits no record. A loader imported from a PyYAML submodule (`from yaml.loader import
  SafeLoader`) is an unresolved loader and stays Review.
- JavaScript and TypeScript: an options value that is not an object literal can carry a schema,
  so `load` and `safeLoad` with such a value stay Review.
- PHP: an options variable suppresses the record only when it is assigned once, by a statement
  that precedes the call, and is used nowhere else. Any other use leaves the options unresolved
  and the record is emitted.

See [coverage and remediation](../detection-capabilities/unsafe-deserialization.md).
