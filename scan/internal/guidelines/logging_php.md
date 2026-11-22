id: zazzles.logging.php
version: 1
languages: php

# PHP sensitive-data logging guidelines

## Logging

For typed PSR-3 loggers (`Psr\Log\LoggerInterface` or `Monolog\Logger`), each level method takes the message and context in arguments 0 and 1. The generic `log` method takes the level first, with message and context in arguments 1 and 2. PHP's `error_log` emits the message in argument 0. Use the source-established binding and inspect whether the message or context receives sensitive content. See the [PSR-3 specification](https://www.php-fig.org/psr/psr-3/) and the [PHP manual for error_log](https://www.php.net/manual/en/function.error-log.php).

Authorization and Cookie headers carry credentials by protocol. Field names such as password, token, and email supply classification hints. Whole request containers may include sensitive fields. Distinguish the original value and any text-preserving transforms from non-revealing facts such as length or presence.

## Do not claim

Only credit redaction when the source shows that it covers the emitted value before the call. Handler behavior, log destinations, access, and retention depend on configuration. An unresolved transformation or field meaning stays uncertain.
