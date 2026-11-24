# Information exposure

Zazzles emits an `info_exposure_candidate` when an HTTP entry reaches a diagnostic operation
whose output is internal state. The record has no request source: the operation, its operand,
its entry and the conditions on the path are the evidence. A judged scan uses them to classify
CWE-200 and CWE-215.

## Rules

| Rule | Fact |
| --- | --- |
| Contract | `php-diagnostic-output-v1`. The operation is a PHP builtin; a project function with the same name is not |
| Operation | `exposure.operation`: `phpinfo`, `debug_print_backtrace`, `var_dump`, `var_export`, `print_r`, `debug_zval_refcount`, `getenv`, `php_uname`, `phpversion`, `ini_get_all`, `dump`, `dd` |
| Subject | `exposure.subject`: `configuration` (`phpinfo`, `ini_get_all`, `get_defined_constants`), `environment` (`$_SERVER`, `$_ENV`, `getenv()`), `runtime_state` (`$GLOBALS`, `get_defined_vars()`, `php_uname`, `phpversion`, framework dumps), `stack` (`debug_print_backtrace`) |
| Flag | `exposure.flag`: a literal `INFO_*` argument of `phpinfo` |
| Output | A returning `print_r`/`var_export` or a value function is recorded at the `echo`, `print`, `Response` body, `setContent` or Twig interpolation that outputs it, and nowhere else. A Twig record carries the conditions that dominate the `render` call |
| Entry | `exposure.entry_served` is `yes` for a server-mapped file or a route. An operation with no HTTP entry records nothing |
| Guards | `exposure.guards` lists dominating `branch_precondition`, `branch_false_precondition` and `configuration_precondition` evidence, including an earlier `if` whose only branch ends in `throw` |
| Records | One candidate per operation per entry |

## Questions and outcomes

Protocol `exposure-components-v1` asks two questions.

| Question | Answers |
| --- | --- |
| `exposure_output` | `internal_state`, `benign`, `unknown` |
| `exposure_reach` | `reachable`, `restricted`, `unknown` |

| Outcome | Condition |
| --- | --- |
| Review (inconsistent) | `restricted` with no recorded guard, or `reachable` with `entry_served: no` |
| Review (blocked) | Gap `diagnostic_output_environment_dependent` |
| Protected | `benign`, or `restricted` with at least one recorded guard |
| Confirmed | `internal_state` and `reachable` |

Required evidence roles are `diagnostic_operation`, `entry` and `control_flow`.

## Bounds

Debug-mode and profiler configuration, exception output and Twig `dump()` are not recorded. A
diagnostic value returned through a helper keeps its marker; one stored and read back does not.

See [coverage and remediation](../detection-capabilities/information-exposure.md).

## JavaScript and TypeScript

The Node contract `node-diagnostic-output-v1` states what `errorhandler`, prom-client `register.metrics()`, swagger-ui-express `setup`, `process.env`, `process.memoryUsage()` and an error `stack` send. A `process.env.NODE_ENV` condition is a guard to weigh, not a fact that the code is absent in production.
