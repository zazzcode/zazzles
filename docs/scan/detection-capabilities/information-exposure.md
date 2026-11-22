# Information exposure

[Detection capabilities](../detection-capabilities.md) · [Analysis rules](../analysis/information-exposure.md)

The `exposure` family records a diagnostic operation whose output reveals server configuration,
environment, runtime state or a call stack, when an HTTP entry reaches it. A judged scan can
report **Information exposure**
([CWE-200](https://cwe.mitre.org/data/definitions/200.html),
[CWE-215](https://cwe.mitre.org/data/definitions/215.html)). Use `--only-family exposure` with
`--analyze --judge` to assess this family alone.

The claim has no request source. It is about an operation that an entry reaches, not a value
that flows from a request.

| Operation | Recorded when |
| --- | --- |
| [`phpinfo()`](https://www.php.net/manual/en/function.phpinfo.php) | Always. A literal `INFO_*` flag is recorded |
| `debug_print_backtrace()` | Always |
| `var_dump`, `debug_zval_refcount`, and `var_export` or `print_r` that print | An argument is `$_SERVER`, `$_ENV`, `$GLOBALS`, `getenv()` with no argument, `get_defined_vars()`, `ini_get_all()` or `get_defined_constants()` |
| `echo`, `print`, a Symfony `Response` body or `setContent`, or a Twig output | The value comes from `getenv()` with no argument, `php_uname()`, `phpversion()`, `ini_get_all()`, or a returning `print_r` or `var_export` over one of the arrays above |
| Symfony `dump()` and `dd()` | Always, in Review (below) |

Plain PHP files under the scanned root and Symfony routes are both entries. An operation
inside a file that runs only from the command line has no entry and records nothing.

## Recorded and decidable

Each record names the operation, what it reveals (`configuration`, `environment`,
`runtime_state` or `stack`), and every condition that dominates it on the path, such as a role
check that throws. A condition is evidence, not a filter. The decision model judges whether it
restricts the caller.

## Recorded in Review

| Gap | Meaning |
| --- | --- |
| `diagnostic_output_environment_dependent` | Symfony `dump()` and `dd()` print only when the debug component is active. Whether a deployment enables it is not in the source |

## Not recorded

- A dump of an ordinary local value, such as an entity or a request object passed to
  `var_dump`. That is a code smell, not this claim.
- A returning `print_r` or `var_export` whose result is never output.
- Debug mode, the web profiler and other configuration-driven exposure.
- Error messages and stack traces returned by exception handling.

## Remediation

Remove the diagnostic call from served code. If a diagnostic page is required, restrict it to an
authenticated administrator and disable it outside development.
