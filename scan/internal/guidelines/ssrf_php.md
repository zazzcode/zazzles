id: zazzles.ssrf.php
version: 1
languages: php

# PHP server-side request forgery guidelines

## Posture

Analyze the verified destination operand independently of request validation, response handling, and local filesystem access. A static claim describes the supplied source evidence.

## Operations

The first argument of `file_get_contents`, `fopen`, `readfile`, `file`, and `copy` can name a stream-wrapper URL. A local path supplies a filesystem operand instead. For cURL, the destination comes from the first argument of `curl_init` or the `CURLOPT_URL` setting. For Symfony `HttpClientInterface::request`, the second argument is the destination. The first argument is the HTTP method.

## Destination control

Distinguish a request-selected URL, a request-selected authority, and a fixed scheme and authority with request data only in the path or query. Treat a destination derived solely from storage or a remote response as an outbound observation.

## Restriction

A source-backed restriction must apply to the same destination value before the request. URL syntax validation establishes format. A literal prefix only fixes the scheme and authority when the prefix completes the authority component.

## Protection coverage

Consider all supported paths reaching the destination. Use redirect restrictions and runtime configuration only when evidence establishes them.

## Do not claim

Do not infer enabled wrappers, DNS results, redirect targets, network topology, or deployment policy. Data in body, headers, or other cURL options does not control the destination on those operands.

References: https://www.php.net/manual/en/wrappers.php and https://symfony.com/doc/6.4/http_client.html.
