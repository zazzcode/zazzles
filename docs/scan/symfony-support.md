# Symfony analysis

[Code Scan](README.md) · [PHP analysis](php-support.md) · [Detection capabilities](detection-capabilities.md)

Code Scan discovers Symfony routes from source, invokes their controller actions in the bounded
PHP analysis, and records source-to-operation evidence for supported library calls. Point the
scanner at the directory that contains the application's Composer manifest.

```sh
go build -o bin/scan ./scan/cmd/scan
./bin/scan --routes --json /path/to/symfony-app
./bin/scan --analyze --output-dir /path/to/findings /path/to/symfony-app
./bin/scan --analyze --entry src/Controller/ArticleController.php \
  --route '/articles/{slug}' --judge openai --output-dir /path/to/findings /path/to/symfony-app
```

`--entry` selects the routes declared by a controller file. `--route` matches the route pattern
including placeholder braces. Omit `--judge` for offline evidence, or configure a
[decision provider](decision-models.md) for assessment. The output directory gets JSON, HTML, and
SARIF reports.

## Entries and inputs

| Area | Supported subset |
|---|---|
| Project | The nearest `composer.json` controls project detection. Its `require` must include `symfony/framework-bundle`. File entries are limited to `public/` or the literal Composer `extra.public-dir`. |
| Entries | PHP route attributes, imported docblock annotations, and YAML route definitions. Each method/path pair has its own entry. An unimported or dynamic route or unresolved controller appears with a dispatch gap. |
| Inputs | Typed `Request` parameter bags, raw and decoded bodies, mapped query fields and request payloads, route placeholders, upload inputs, and PHP superglobals. Fixed entry methods narrow supported method comparisons. |
| Services | Source-declared types, service aliases and constructor arguments from allow-listed YAML, promoted properties and bounded method tracing. Environment-dependent values are configuration evidence on the path. |
| Storage | Doctrine entity arguments, the session user, finder and query results, mapped fields and associations. A storage link connects a possible request writer with a reader. |
| Twig | Literal templates from the walk inventory, render context, supported filters, and project Twig extension calls. The outermost output operation and the HTML context determine encoding evidence. |

Library references for [routing](https://symfony.com/doc/6.4/routing.html),
[request and response handling](https://symfony.com/doc/6.4/components/http_foundation.html),
[dependency injection](https://symfony.com/doc/6.4/service_container.html), and
[Twig syntax](https://twig.symfony.com/doc/3.x/).

## Operations

| Family | Symfony evidence |
|---|---|
| SQL | Verified Doctrine DBAL statements, prepared execution, ORM DQL and native queries, and QueryBuilder text construction. Parameter bindings apply to their data slots. |
| XSS | HTML `Response` content and Twig output in the actual HTML context. The report distinguishes ordinary autoescape, explicit strategies, raw output, and unresolved expressions. |
| Command | PHP shell APIs in resolved services and Symfony `Process`. An argument vector and a shell command string carry different operand evidence. |
| Path | PHP local file operations, `BinaryFileResponse`, and the controller `file()` helper. |
| Upload | `UploadedFile::move` destination and stored name, including whether the destination is served, how the extension is chosen, and which type controls apply before the write. |
| SSRF and outbound | Verified PHP URL-capable operations, cURL destination slots, and Symfony HttpClient. Outbound observations use destination evidence without requesting a vulnerability judgment. |
| Code and template injection | PHP interpreter calls inside reached methods and verified Twig compilation reached through a template function. |
| Deserialization | PHP `unserialize` and verified `Yaml::parse` in reached controllers and services, including services wired as Twig globals. |
| Redirect | Controller `redirect()` and `RedirectResponse` destination operands. `redirectToRoute()` resolves an internal route name. |
| Logging | Verified PSR-3 method and `error_log` emission of a value with a sensitive-data source. |
| Validation | Automatic PHP query checks use source-backed request field names and control evidence. |
| NoSQL and prototype pollution | Outside Symfony coverage. Doctrine MongoDB ODM needs its own model. |

Library references for [Doctrine DBAL](https://www.doctrine-project.org/projects/doctrine-dbal/en/3.10/reference/data-retrieval-and-manipulation.html),
[Doctrine ORM QueryBuilder](https://www.doctrine-project.org/projects/doctrine-orm/en/2.20/reference/query-builder.html),
[Symfony Process](https://symfony.com/doc/6.4/components/process.html),
[Symfony HttpClient](https://symfony.com/doc/6.4/http_client.html), and
[PSR-3](https://www.php-fig.org/psr/psr-3/).

## Bounds

- Analysis reads project source and the configuration and template allow-lists. It leaves
  `vendor/` and the Symfony project's `var/` out of PHP analysis. It does not execute Composer,
  Symfony Console, controllers, templates, or the dependency injection container.
- Configuration files are limited to 1 MiB. Symlinks, unreadable files, unsupported YAML tags,
  and unresolved values surface as gaps. Environment alternatives stay distinct from base values.
  PHP helpers are bounded to depth four and 256 calls per entry.
- XML and PHP route definitions, API Platform, Symfony Forms, Validator constraints, event
  subscribers, Messenger handlers and console entry points are outside route discovery. Console
  code can contribute a non-entry storage writer.
- Twig macros, `embed` overrides, dynamic template names, sandbox policy, and mail HTML are
  outside the supported render subset. Doctrine XML and YAML mappings, custom naming strategies,
  full DQL parsing and lifecycle listeners are outside the storage model.
- Other frameworks use their own adapters. Authorization, mass assignment, CSRF, secrets,
  session cookie policy, and cryptography are outside these claims. Security configuration can
  supply entry context. Protection evidence belongs to the actual sink and value path.
