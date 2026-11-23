# Symfony analysis

[Code Scan](README.md) · [PHP analysis](php-support.md) · [Detection capabilities](detection-capabilities.md) · [Symfony coverage](detection-capabilities/symfony.md) · [Twig coverage](detection-capabilities/twig.md)

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
| Entries | PHP route attributes on actions, classes and invokable controllers, imported docblock annotations, and YAML route definitions. Each method/path pair has its own entry. An unimported or dynamic route or unresolved controller appears with a dispatch gap. |
| Inputs | Typed `Request` parameter bags and their typed readers, raw and decoded bodies, mapped query fields and request payloads, route placeholders with inline requirements and defaults, upload inputs, and PHP superglobals. An `int`, `float` or `bool` argument is a numeric value. Fixed entry methods narrow supported method comparisons. |
| Services | Source-declared types, service aliases and constructor arguments from allow-listed YAML, promoted properties and bounded method tracing. Environment-dependent values are configuration evidence on the path. |
| Storage | Doctrine entity arguments, the session user, finder and query results, mapped fields and associations. A storage link connects a possible request writer with a reader. A numeric-typed field is not rendering content. |
| Twig | Literal templates from the walk inventory, render context, supported filters, and project Twig extension calls. The outermost output operation, the autoescape strategy and the surrounding markup determine encoding evidence. [Twig coverage](detection-capabilities/twig.md) lists each output form. |

Library references for [routing](https://symfony.com/doc/6.4/routing.html),
[request and response handling](https://symfony.com/doc/6.4/components/http_foundation.html),
[dependency injection](https://symfony.com/doc/6.4/service_container.html), and
[Twig syntax](https://twig.symfony.com/doc/3.x/).

## Operations

| Family | Symfony evidence |
|---|---|
| SQL | Verified Doctrine DBAL statements, prepared execution, ORM DQL and native queries, and QueryBuilder text construction. Parameter bindings apply to their data slots. A chain keeps its query text through pagination and cache setters. |
| XSS | HTML `Response` content, `Response::setContent`, and Twig output in the actual HTML context. The report distinguishes ordinary autoescape, explicit strategies, raw output, URL attributes, and unresolved expressions. |
| Command | PHP shell APIs and backtick commands in resolved services, and Symfony `Process`. An argument vector and a shell command string carry different operand evidence. |
| Path | PHP local file operations, `BinaryFileResponse`, and the controller `file()` helper. |
| Upload | `UploadedFile::move` destination and stored name, including whether the destination is served, how the extension is chosen, and which type controls apply before the write. |
| SSRF and outbound | Verified PHP URL-capable operations, cURL destination slots, and Symfony HttpClient. Outbound observations use destination evidence without requesting a vulnerability judgment. |
| Code and template injection | PHP interpreter calls inside reached methods and verified Twig compilation reached through a template function. |
| Deserialization | PHP `unserialize` and verified `Yaml::parse` in reached controllers and services, including services wired as Twig globals. |
| Redirect | Controller `redirect()` and `RedirectResponse` destination operands. `redirectToRoute()` resolves an internal route name. |
| Information exposure | `phpinfo()`, backtraces and environment dumps reached from routes and served files, with dominating guards as evidence. `dump()` and `dd()` stay in Review. |
| Authorization | A stored write, a file write or delete, or a census-field read, with the entry's access and the guards that dominate the operation ([analysis rules](analysis/authorization.md)) |
| Account | Account enumeration from finder branches, recovery secrets delivered through Symfony Mailer, and fast password digests stored as credentials, in hasher classes or in `password_hashers` (family `account`, [analysis rules](analysis/account-security.md)) |
| Mass assignment | Whole request bags iterated into dynamic property writes, `set…` dispatch, `PropertyAccessor::setValue` or reflection on an entity, with the census roles of its fields. Form, serializer and payload mapping stay in Review. |
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
- Twig macro bodies, `embed` overrides, dynamic template names, sandbox policy, and mail HTML are
  outside the supported render subset. A macro definition and a macro call are recorded as gaps. Doctrine XML and YAML mappings, custom naming strategies,
  full DQL parsing and lifecycle listeners are outside the storage model.
- Other frameworks use their own adapters. The Symfony website claims are information exposure,
  mass assignment, authorization, account security, insecure configuration, and SSRF including a
  `curl` or `wget` shell URL. Committed secrets, voters, custom authenticators, and Form or
  serializer mass assignment stay outside.
  [Symfony coverage](detection-capabilities/symfony.md#outside-these-claims) Security configuration supplies
  entry access for the authorization claim. Protection evidence belongs to the actual sink and value path.
