# PHP Symfony support — vuln-symfony and Symfony applications

- **Status** Proposal, drafted 2026-11-19. No code is written. Implementation starts on owner assignment.
- **Worktree and branch** Owner's choice (§11 OQ-1). This spec is drafted in
  `close-findings-gaps-dvwa` and may be implemented in a separate `php-symfony` sibling worktree.
- **Baseline** `stage` at `58e94e7`
- **Supersedes** [Architecture phase 6 — Symfony registration resolver](architecture-phase-6-symfony.md).
  Phase 6 was written before the PHP package, the project-resolution groundwork and a pinned
  sample existed. It stays as history. This contract keeps its D-3 to D-6 and replaces its scope.
- **Prerequisite** [Close findings gaps](close-findings-gaps.md) W3 (PHP class, method and property
  binding). Slice S6 also needs its W5 (upload claim) and W6 (template-injection claim).
- **Delivery** One draft PR into `stage` per slice group in §9, each reviewable alone.
- **Run log** `.zazz/ephemeral/php-symfony-support-run-log.md`

## 1. Capability

Analyze Symfony applications through the existing PHP adapter, evidence model and analyzers.
The scanner learns four things about Symfony and adds no new flow engine:

1. **Where requests enter.** Controller routes become HTTP entries that dispatch to action methods.
2. **How values arrive.** The `Request` object, route placeholders, entity arguments and autowired
   services bind to action parameters.
3. **Where values go.** Doctrine DBAL and ORM, Twig, `Response`, `Process`, `UploadedFile` and the
   HTTP client are modeled as library contracts on the existing SQL, XSS, command, path, SSRF,
   redirect and code families.
4. **What is stored.** Doctrine entity fields are storage keys, so stored flows link writers to
   readers as SQL columns do today.

The acceptance target is the owner's sample `zazzcode/vuln-symfony`, a fork of
`Secureaks/VulnerableSymfony` (Symfony 6.4, Doctrine ORM 2, Twig 3, PHP 8.1 attributes).

### Baseline today

An offline scan of the sample at `086f81f` with the scanner at `58e94e7`:

| Measure | Today |
|---|---|
| Entries | 28: 25 false `FILE` entries for files under `src/`, `config/`, `migrations/` and `tests/`, 2 real ones under `public/`, and 1 browser script. No route entry |
| Candidates | 1 (`public/js/script.js:6`, `innerText`, correctly Protected) |
| The sample's documented vulnerabilities found | 0 |

Three causes, all structural:

- Every `.php` file is treated as a server-mapped page. Symfony serves only `public/`.
- Method bodies are reached only through `new C` of a class in the same file, so no controller,
  repository or service body is walked.
- `Request`, Doctrine and Twig have no models. `.twig` files are not read.

The Symfony service reader in `internal/langphp/project_resolution.go` also rejects the sample's
`config/services.yaml` (flow-style `{ name: twig.extension }`, nested `arguments`). It then marks
the project invalid, which blocks every reference resolution, including plain PSR-4 lookups.

### Sample answer key (source-reviewed at `086f81f`)

Paths are relative to the sample root. This table becomes
`.zazz/evaluation/vuln-symfony-detection-guide.md` in slice S0.

| ID | Entry and source | Operation and expected defect | Family | Slice |
|---|---|---|---|---|
| `SYM-SQL-01` | `GET /search`, `s` at `src/Controller/BlogController.php:70` | Concatenated into SQL at `src/Repository/PostRepository.php:64`, run by DBAL `prepare` and `executeQuery([])` at `:66`–`67` | SQL | S3 |
| `SYM-SQL-02` | `POST /login`, `email` at `src/Controller/LoginController.php:22` | Interpolated into SQL at `src/Repository/UserRepository.php:74`, run at `:76`–`77`. The `password` operand is an `md5` hash and carries no content path | SQL | S3 |
| `SYM-XSS-01` | `GET /search`, `s` | Rendered by `{{ search \| raw }}` at `templates/blog/index.html.twig:11` | XSS, reflected | S4 |
| `SYM-XSS-02` | `POST /post/{post}/comment`, `comment` at `BlogController.php:56`, read on `/post/{post}` | Stored in `Comment.content`, rendered by `{{ comment.content \| raw }}` at `templates/blog/post.html.twig:40` | XSS, stored | S4 |
| `SYM-CMD-01` | `/` and `/post/{post}`, `Referer` header at `src/Services/Analytics.php:25` | `shell_exec('curl … ' . $referer)` at `:31`–`32`, guarded only by `FILTER_VALIDATE_URL` (`:40`). Reached through the injected `Analytics` service (`BlogController.php:23`, `:35`) behind the `trackingEnabled` configuration flag | Command | S5 |
| `SYM-PATH-01` | `GET /legal/content`, `p` at `BlogController.php:91` | `file_get_contents` of a concatenated path at `:95`. `is_dir` and `file_exists` do not contain it | Path | S5 |
| `SYM-SSRF-01` | `POST /user/avatar/url/{user}`, `url` at `src/Controller/UserController.php:123` | `file_get_contents($url)` at `src/Services/Avatar.php:18`: a request-controlled URL and a whole-operand file read | SSRF, path | S5 |
| `SYM-UPLOAD-01` | `POST /user/avatar/{user}`, uploaded file at `UserController.php:85` | Stored under `public/uploads/avatars` with the client's extension (`:98`–`99`) | Upload | S6 |
| `SYM-SSTI-01` | `POST /user/about/`, `about` at `UserController.php:213`, read on `/post/{post}` | Stored in `User.aboutMe`, compiled by `template_from_string(…)` at `templates/blog/post.html.twig:37` through `createTemplate` at `src/Twig/TemplateFromStringExtension.php:22` | Template injection, stored | S6 |
| `SYM-CMD-02` (Review-expected) | `GET /user/avatar/resize/{user}` | `shell_exec('convert ' . $avatarFile …)` at `UserController.php:193`–`195`. `$avatar` is the stored `User.avatar`, written with a client extension at `:98`–`101` and by the wildcard write at `:239` | Command, stored | S5 |

Required controls, none of which may be a finding:

| ID | Location | Why it is safe for its claim |
|---|---|---|
| `SYM-SQL-N01`–`N03` | `src/Repository/CommentRepository.php:52`–`57`, `:62`–`67`; `PostRepository.php:72`–`77` | QueryBuilder text is constant; values bind through `setParameter` |
| `SYM-SQL-N04` | `LoginController.php:76`, `:83`; `PasswordResetController.php:64` | `findOneBy` criteria arrays bind their values |
| `SYM-XSS-N01` | `templates/blog/post.html.twig:12`, `:13`, `:35`; `templates/user/index.html.twig:8`–`14` | Autoescaped `{{ }}` in HTML text |
| `SYM-XSS-N02` | `templates/user/edit.html.twig:14`, `:16` | Autoescaped in a quoted attribute |
| `SYM-XSS-N03` | `templates/blog/post.html.twig:20`, `{{ post.content \| nl2br }}` | `nl2br` escapes its input first |
| `SYM-XSS-N04` | `public/js/script.js:6` | `innerText` (already Protected today) |
| `SYM-REDIR-N01` | Every `redirectToRoute(…)` call | The target is a route name, not a request URL |

Not covered by any analyzer, and recorded as such in the guide:

- Missing authorization on six `/user/…` and `/admin/…` actions.
- Mass assignment (`src/Entity/User.php:56`–`61`, `PasswordResetController.php:34`).
- Unsafe deserialization of the `USER_PREF` cookie (`src/Services/UserPref.php:35`–`36`). The sample's
  README does not list it. The [deserialization contract](unsafe-deserialization.md) owns this row
  (`SYM-DESER-01`); D-16 here makes the call reachable.
- User enumeration, MD5 password hashing, `phpinfo()` at `public/info.php`, directory listing,
  secrets in `.env`, and the cron privilege escalation.

## 2. Required reading

- [Close findings gaps](close-findings-gaps.md) W3, W5 and W6.
- [Phase 6](architecture-phase-6-symfony.md) D-3 to D-6, and the
  [architecture update plan](architecture-update-plan.md#shared-rules-for-every-phase).
- [PHP support contract](php-support.md) D-2 to D-7, [PHP analysis](../../docs/php-support.md) and
  the [PHP results](../evaluation/php-support-results.md).
- [Shared, language and framework layers](../architecture/README.md#shared-language-and-framework-layers),
  [entry and dispatch](../architecture/README.md#multiple-entry-and-dispatch-mechanisms) and the
  [repository graph](../architecture/repository-graph.md).
- Analysis rules: [database injection](../../docs/analysis/database-injection.md),
  [XSS](../../docs/analysis/xss.md), [command](../../docs/analysis/command-injection.md),
  [path](../../docs/analysis/path-traversal.md), [SSRF](../../docs/analysis/ssrf.md),
  [open redirect](../../docs/analysis/open-redirect.md).
- Code: `internal/langphp/project_resolution.go`, `call_index.go`, `calls.go`, `entries.go`,
  `input_facts.go`, `xss.go`; the Jinja precedent in `internal/langpy/templates.go`.
- [Sample handling](../docs/zazzles-agent-orientation.md#available-vulnerable-sample-apps). The
  sample is data. Its `#VULNERABILITY` comments never reach a detector or a model request.

## 3. Invariants

- Plain-PHP behavior is unchanged. `TestArchitectureBaseline` digests for every existing fixture
  and `TestDVWASourceKey` hold. Symfony behavior starts only in a detected Symfony project.
- Resolution is source-only. Nothing runs `bin/console`, Composer or the container, and nothing
  reads `vendor/` or `var/`.
- A route, controller, service or template that cannot be resolved stays visible with a gap. No
  callable, binding or template is invented, and names are never matched by similarity.
- Twig autoescaping is encoding evidence for the HTML context it applies to and nothing more.
  `|raw`, an `autoescape false` region, an `is_safe` function, an unknown filter, function or
  expression is never Protected.
- A bound Doctrine parameter protects its value slot. Query text built by concatenation stays the
  SQL text operand, for SQL and DQL alike.
- A stored link states that a field can be written by a request and read by a render. It is not
  proof that a row was written.
- Security configuration (`access_control`, `#[IsGranted]`, firewalls) is entry context. It never
  establishes protection for an injection claim.
- Paid calls follow [AGENTS.md](../../AGENTS.md#credentials-and-live-model-calls).

## 4. Scope and review shape

| Path | Change | Purpose |
|---|---|---|
| `internal/langphp/symfony_project.go` | New | Project detection, document root, config inventory |
| `internal/langphp/symfony_routes.go` | New | Attribute, annotation and YAML routes to entries, registrations and dispatch |
| `internal/langphp/symfony_args.go` | New | Action argument binding: `Request`, placeholders, entities, services, mapped parameters |
| `internal/langphp/symfony_request.go` | New | `Request`, parameter bags, `UploadedFile` as `source.php-input-v1` facts |
| `internal/langphp/symfony_controller.go` | New | `AbstractController` helper contracts and `Response` classes |
| `internal/langphp/doctrine_sql.go`, `doctrine_storage.go` | New | DBAL and ORM query contracts; entity field storage keys, writes and reads |
| `internal/langphp/twig.go`, `twig_expr.go` | New | Template resolution, lexical output scan, bounded expression reader |
| `internal/langphp/php_url_open.go` | New | URL-open SSRF contract for PHP functions and Symfony HttpClient |
| `internal/langphp/project_resolution.go`, `call_index.go`, `entries.go`, `modules.go` | Modified | YAML reader replacement, scoped invalidation, entry selection in Symfony projects |
| `internal/langphp/*_test.go`, `internal/langphp/testdata/symfony/<case>/` | New | Paired fixtures (§8) |
| `internal/walk/walk.go`, tests | Modified | `Result.Config` and `Result.Templates` name allow-lists. Neither is a language |
| `internal/analysis` (entry mechanisms, HTTP metadata), `internal/analysispacks`, `internal/guidelines` | Modified | Mechanisms `attribute_route`, `annotation_route`, `config_route`; contracts `php-doctrine-dbal-v1`, `php-doctrine-orm-v1`, `twig-output-v1`, `symfony-response-v1`, `symfony-process-v1`, `php-url-open-v1`; `filter_var` guard contracts |
| `internal/pipeline/symfony_test.go` | New | `TestSymfonySourceKey`, enabled by `ZAZZLES_VULN_SYMFONY` |
| `go.mod`, `go.sum` | Modified | `gopkg.in/yaml.v3` (approved, OQ-2) |
| `docs/php-support.md`, `docs/symfony-support.md` (new), `docs/detection-capabilities.md`, `docs/analysis/{database-injection,xss,ssrf}.md`, `README.md` | Modified, new | Supported subset and limits |
| `.zazz/evaluation/vuln-symfony-detection-guide.md`, `symfony-results.md`, `recall-gap-inventory/cases.json`, `.zazz/project/vulnerable-sample-apps.md`, `.zazz/project/implementation-plan.md`, `.zazz/architecture/README.md` | New, modified | Key, results, catalog, capability checklist |
| `docs/samples/vuln-symfony/` | New | Published sample report with attribution (D-22) |
| `cmd/scan/testdata/architecture-baseline.json` | Modified | New Symfony fixture rows only |

Out of scope:

- Authorization, mass assignment, deserialization, CSRF, secrets and cryptography analyzers.
- XML and PHP-file route definitions (a gap when present), API Platform, Symfony Forms and
  Validator constraint semantics, event subscribers and console commands as entries, Messenger.
- Full Twig grammar: macros, `embed` overrides, dynamic template names, sandbox policy.
- Doctrine XML or YAML mappings, custom naming strategies, DQL parsing, lifecycle listeners.
- Other frameworks. Laravel and Drupal ([phase 9](architecture-phase-9-drupal.md)) reuse
  W3 and the project layer, not this adapter.

## 5. Decisions

### Project and entries

- **D-1. Detection.** A directory is a Symfony project when its `composer.json` requires
  `symfony/framework-bundle`. The nearest `composer.json` above a file decides, so a Symfony app
  nested in a larger repository is detected without changing its neighbours.
- **D-2. Only the document root is file-mapped.** In a Symfony project, `.php` files under
  `public/` keep `server_file_mapping` entries. Files elsewhere are not entries.
  **Why.** `src/` is not web-reachable, so 25 of today's file entries are false. `public/index.php`
  stays, as phase 6 D-5 requires, and so does `public/info.php`.
  **Bound.** The document root is `public/` unless `composer.json` `extra.public-dir` names another.
- **D-3. PHP source decides before configuration.** A type-hinted class resolves through the
  declared-name index and PSR-4 without `services.yaml`. Configuration adds aliases, interface
  bindings, parameters and route imports. A config file the reader cannot parse records
  `symfony_config_unread` on what depended on it and no longer invalidates the project.
  **Why.** One flow-style line in `services.yaml` currently disables all resolution.
- **D-4. Routes.** Three sources, each a `static` registration:
  - PHP 8 `#[Route]`, resolved through `use` to `Symfony\Component\Routing\Attribute\Route` or
    `…\Annotation\Route`: path, `name`, `methods`, `requirements`, `defaults`, repeated attributes,
    and the class-level path and name prefix. Mechanism `attribute_route`.
  - Docblock `@Route` with the same fields. Mechanism `annotation_route`.
  - `config/routes.yaml` and `config/routes/*.yaml`: explicit `path` and `controller` routes, and
    `resource` imports of `type: attribute` or `annotation` with `prefix` and `name_prefix`.
    Mechanism `config_route`.
- **D-5. Import evidence.** An attribute route is `resolved` when a readable routing file imports
  its class or directory. When routing config exists but does not import it, the registration is
  `unresolved` with `symfony_route_not_imported`. When no routing config is readable, the route
  resolves with a `symfony_config_unread` note.
  **Why.** An attribute alone does not register a route in Symfony. The scanner reports the
  registration it can show and says when it could not check.
- **D-6. Entry identity.** One entry per method and path: `GET /search`. A route with no `methods`
  is one `ANY` entry. `{name}` placeholders are `framework_pattern` path parameters. The sample's
  29 method-level route attributes (two of them `GET` and `POST`) yield 31 entries.
- **D-7. Controller resolution** uses phase 6 D-3 (PSR-4, `Class::method`, `__invoke`). A service
  ID, a closure or a missing class or method is an unresolved dispatch with a gap.

### Arguments and inputs

- **D-8. Action arguments bind by declared type.**

  | Parameter | Binding |
  |---|---|
  | `Request` | The request object (D-9) |
  | Scalar whose name matches a `{placeholder}` | Path input fact, role `attributes` |
  | `#[MapQueryParameter]`, `#[MapQueryString]`, `#[MapRequestPayload]` | Query or body input fact. A mapped DTO's fields are request-derived; its constraints are not read |
  | Entity class whose name matches a placeholder | An entity loaded by a request-chosen identifier. Its fields carry stored origin (D-14); the identifier is bound by the ORM and makes no SQL claim |
  | `#[CurrentUser]` and `$this->getUser()` | The session user entity, stored origin |
  | Another resolvable class or interface | An autowired object. Its constructor runs with autowired arguments; scalar arguments come from configuration and are `configuration` origin, not request input |
  | Anything else | Unknown value with `symfony_argument_unresolved` |

- **D-9. Request sources.** These map to the existing `source.php-input-v1` roles
  (phase 6 D-6). No fact schema bump is expected; if one is needed, halt.

  | API | Role |
  |---|---|
  | `$request->query->get/all/…` | `query` |
  | `$request->request->get/all`, `getPayload()`, `toArray()` | `body` |
  | `$request->attributes->get` | `path` |
  | `$request->cookies`, `->headers`, `->server` | `cookie`, `header`, server (existing `$_SERVER` key policy) |
  | `$request->files->get` | `files` |
  | `$request->getContent()` | raw body |
  | `$request->get('k')` | `request_any`: Symfony reads path, then query, then body |
  | `getUri`, `getPathInfo`, `getQueryString`, `getClientIp`, `getHost` | URL or client-influenced values |
  | `getInt`, `getBoolean`, `getDigits`, `getAlpha`, `getAlnum`, `getEnum` | The same role with a typed-conversion transform, recorded as a guard fact with its contract |
  | `UploadedFile::getClientOriginalName`, `getClientOriginalExtension`, `getClientMimeType` | Client-controlled file metadata |
  | `UploadedFile::guessExtension`, `getMimeType` | Content-derived metadata |

  Superglobals inside services keep working (`$_SERVER['HTTP_REFERER']` in `Analytics`).
- **D-10. Services.** Constructor-promoted properties hold their autowired objects (W3 D-10), so
  `$this->repo->search($s)` expands through the bounded helper engine. A scalar constructor
  argument that guards a branch is kept as a configuration precondition on the path, as Juice
  Shop's challenge flags are. It neither blocks nor proves reachability.
- **D-11. `AbstractController` helpers** are contracts, not expanded source (the class is in
  `vendor/`): `render` and `renderView` (D-16), `redirectToRoute` (internal, no redirect claim),
  `redirect` and `RedirectResponse` (redirect destination), `json`, `file` and `BinaryFileResponse`
  (path operand), `getParameter` (D-12), `addFlash` (session storage read by `app.flashes`),
  `createNotFoundException` (terminator).
- **D-12. Parameters.** `getParameter('k')` and `%k%` resolve from `parameters:` in
  `config/services.yaml` when the value is a literal or `%kernel.project_dir%/…`. That makes
  `public/uploads/avatars` a known, served directory. `%env(…)%` values are `configuration` origin.

### Sinks and storage

- **D-13. Doctrine SQL.** Receivers resolve by declared type: `Connection`,
  `EntityManagerInterface`, `ManagerRegistry`, and repositories extending `ServiceEntityRepository`
  or `EntityRepository`.
  - DBAL (`php-doctrine-dbal-v1`): `executeQuery`, `executeStatement`, `fetchOne`,
    `fetchAssociative`, `fetchAllAssociative` and siblings, `prepare` with
    `Statement::bindValue`, `executeQuery(params)` and `executeStatement(params)`. The SQL text is
    the operand; the parameter array and bound values are binding controls.
  - ORM (`php-doctrine-orm-v1`): `createQuery(dql)`, `createNativeQuery`, and QueryBuilder text
    methods (`where`, `andWhere`, `orWhere`, `having`, `orderBy`, `select`, `join` conditions) with
    `setParameter` and `setParameters` as bindings.
  - Finders (`find`, `findBy`, `findOneBy`, `findAll`, `count`, magic `findOneByX`) bind their
    criteria. They are storage reads and make no SQL claim.
  - An `orderBy` or identifier position fed by a request value stays a candidate, because binding
    does not protect identifiers.
- **D-14. Entity fields are storage keys.** A class with `#[ORM\Entity]` (or `@ORM\Entity`) maps
  each `#[ORM\Column]` property to `php-sql:<table>.<column>`, using `#[ORM\Table]` and
  `#[ORM\Column(name:)]` or Doctrine's default naming. A configured non-default naming strategy
  leaves the mapping unresolved with a gap.
  - **Write.** A setter or property assignment on an entity that is managed (loaded) or reaches
    `persist` in the same invocation, directly or through a resolved helper such as a repository
    `save`.
  - **Wildcard write.** A dynamic property write (`$this->$key = $value`) fed by a request bag is
    recorded as a request writer of every mapped field of that class.
  - **Read.** A getter or property access on an entity from a finder, a QueryBuilder result, an
    entity argument or `getUser()`, and an array row from DBAL keyed by column name.
  - Associations follow the property's declared type or `targetEntity` to depth 3.
  **Why.** One key space lets a raw DBAL read (`SELECT * FROM post`) and an ORM write of the same
  column link, and reuses the existing stored-origin census, `closed_store` fact and resolution
  questions unchanged.
- **D-15. `Response` output.** `new Response($content)` is an HTML response sink unless a
  non-HTML `Content-Type` is set by a literal header. `JsonResponse` and `$this->json` are not HTML
  sinks. A variable or computed content type is `render_protection_unresolved`.
- **D-16. Twig is a bounded lexical scan** (phase 6 D-4, extended). Templates resolve under
  `templates/` or the literal `twig.default_path`. The scanner reads:
  - `{{ expr }}`, `{% … %}` and `{# … #}` regions, and the surrounding HTML for the output context
    with the existing inline-HTML classifier (text, quoted attribute, URL attribute, script, style).
  - Expressions of the form variable, attribute chain (`a.b.c`, `a['k']`), filter chain and a
    function call with such arguments. Anything else is `twig_expression_unresolved`.
  - Variables from the `render` context array, `{% for x in xs %}` element bindings, `{% set %}`,
    and `{% include %}`, `{% extends %}` and `{{ include() }}` with literal names, which share the
    context. `app.request.query.get('k')` and `app.request.get('k')` are direct request sources.
    `app.flashes` reads the flash storage. `app.user` is the session user entity.
  - Attribute access on an entity or row resolves to its storage key (D-14).
  - Autoescape by template name: `.html.twig` is HTML strategy. Encoded applies to HTML text and
    quoted attributes. An autoescaped value inside `<script>`, an unquoted attribute or a URL
    attribute is not credited and stays a candidate with the context recorded.
  - Filters by contract: `raw` removes escaping; `e` and `escape` apply the named strategy;
    `nl2br` escapes first; value-preserving filters (`upper`, `trim`, `date`, `length`, `default`
    and similar) keep autoescaping. An unknown filter is a gap.
  - `{% autoescape false %}` regions are raw.
  - Project Twig extensions: a function or filter registered with `is_safe` containing `html` is
    raw output, and its PHP callable is resolved and expanded with the template arguments.
  - Twig `globals` in `config/packages/twig.yaml` that name a service (`'@App\…'`) construct that
    service for a render. Its constructor is expanded once per rendering entry, and records at one
    sink group under it.
  **Why.** This is the Jinja precedent with the Twig facts the sample exercises. A full grammar
  would not add a row to the key.
- **D-17. Command, path and upload.** Existing PHP sinks apply inside methods once W3 lands. Added
  contracts: `Process::fromShellCommandline` (shell text) and `new Process([argv])` (no shell);
  `UploadedFile::move($dir, $name)` as an upload write with both operands; `BinaryFileResponse` and
  `file()` as path reads.
- **D-18. PHP URL open is an SSRF contract** (`php-url-open-v1`): `file_get_contents`, `fopen`,
  `readfile`, `copy` source, `curl_init($url)` and `curl_setopt(…, CURLOPT_URL, $url)`, and
  Symfony `HttpClientInterface::request($method, $url)`. A request-derived destination makes an
  SSRF claim. For the stream functions the filesystem read claim coexists, because the same
  operand accepts a local path and wrappers such as `file://` and `php://`.
  **Why.** PHP has no SSRF contract today, and one operand carries both defects in the sample.
- **D-19. Guard contracts.** Add `filter_var` with `FILTER_VALIDATE_URL`, `FILTER_VALIDATE_EMAIL`,
  `FILTER_VALIDATE_INT` and `FILTER_VALIDATE_IP` to the guard contract table, each stating the
  accepted set from the PHP manual. `FILTER_VALIDATE_URL` checks URL structure; its contract must
  state which shell metacharacters a valid URL can still contain. The text is source-reviewed at
  implementation and never asserts adequacy.

### Configuration reading

- **D-20. YAML.** Replace the hand-written block-map reader with `gopkg.in/yaml.v3` (pure Go,
  approved by the owner on 2026-11-19), limited to the allow-listed files: `config/routes.yaml`,
  `config/routes/*.yaml`, `config/services.yaml`, `config/packages/twig.yaml`, `doctrine.yaml` and
  `security.yaml`. Files over 1 MiB, symlinks and
  unsupported tags are gaps.
  **Why.** A default Symfony skeleton uses flow maps, lists and nested arguments. The current
  reader rejects all three, and extending it by hand means reimplementing YAML.
- **D-21. `when@env` blocks** are read as alternatives, never merged. A value that differs between
  environments is `configuration` origin.
- **D-22. The sample report is published like every other sample** (owner decision, 2026-11-19):
  HTML, JSON and SARIF under `docs/samples/vuln-symfony/`, with the upstream license as
  `SOURCE-LICENSE.txt` and a README that credits the upstream project and names the pin.

## 6. Agent implementation rules

Follow the [common rules](architecture-update-plan.md#common-agent-implementation-rules) and
[execution discipline](../docs/agent-execution-discipline.md). Halt and ask when:

- An existing PHP fixture digest or a DVWA keyed outcome changes.
- An input fact version bump is needed (D-9).
- W3 of the gaps contract is not merged and a slice other than S0 or S1 is about to start.
- A slice would need to read `vendor/` to make a key row pass.

Fixtures are written for this contract. No fixture copies sample source.

## 7. Acceptance criteria

1. **AC1 (S0, key).** The detection guide holds the §1 key with source evidence per row. The sample
   is in the catalog at `086f81f`. `check.py` scores it, and the offline baseline (0 of 9 required
   positives) is recorded in `symfony-results.md`.
2. **AC2 (S1, entries).** A fixture controller with class `#[Route('/blog', name: 'blog_')]` and
   method `#[Route('/{slug}', methods: ['GET'])]`, imported by `routes.yaml`, yields one
   `GET /blog/{slug}` entry: `static`, `attribute_route`, `resolved`, dispatching to the method.
   A file under `src/` yields no `FILE` entry. `public/index.php` still does. A class outside the
   imported resource yields an `unresolved` registration with `symfony_route_not_imported`. A
   plain-PHP fixture is unchanged.
3. **AC3 (S1, config).** An explicit `routes.yaml` route with `controller: App\Controller\X::show`
   resolves. A missing controller class stays in the report as `unresolved`. A `services.yaml` the
   reader cannot parse records `symfony_config_unread` and PSR-4 resolution still works.
4. **AC4 (S2, inputs).** `$request->query->get('q')`, `$request->get('q')`, an `{id}` scalar
   argument, `#[MapQueryParameter] string $q` and a header read each reach a sink as request-origin
   facts with role and name. `getInt('n')` records its conversion. An entity argument's getter
   carries stored origin, not request origin.
5. **AC5 (S3, SQL pairs).**
   - `$conn->executeQuery("… WHERE id = " . $id)` and `$conn->prepare($sql)->executeQuery([])` with
     concatenated `$sql`, called from a controller through an injected repository, are SQL
     candidates with the request source.
   - `executeQuery("… WHERE id = ?", [$id])` and `->where('u.name = :n')->setParameter('n', $n)`
     carry binding witnesses and are not Confirmed.
   - `->where("u.name = '" . $n . "'")` and `createQuery("… " . $n)` are candidates.
   - `findOneBy(['email' => $email])` makes no SQL claim.
   - An unresolvable receiver gives a gap and no claim.
6. **AC6 (S4, output pairs).**
   - `new Response('<p>' . $q . '</p>')` is a raw XSS candidate; `new JsonResponse($q)` is none.
   - `{{ q }}` in HTML text is encoded. `{{ q|raw }}`, an `autoescape false` region and an
     `is_safe` project function are raw candidates. `{{ q }}` inside `<script>` is a candidate with
     script context. An unknown filter gives `twig_expression_unresolved`.
   - A value passed through `{% include %}` and a `{% for %}` element keep their sources.
   - A setter write of a request value on a persisted entity links to a `{{ e.field|raw }}` read in
     another entry as a stored claim with the writing entry named. A field with only literal
     writers carries no request content.
7. **AC7 (S5, services).** A controller that calls an injected service whose method reads
   `$_SERVER['HTTP_REFERER']`, checks it with a `filter_var` helper and passes it to `shell_exec`
   yields a command candidate under the controller's entry, with the guard recorded, its contract
   attached and the configuration flag kept as a precondition. A `file_get_contents($url)` in a
   service with a request URL yields both an SSRF and a filesystem-read claim. A constant URL
   yields neither.
8. **AC8 (S6).** With gaps W5 and W6 merged: `UploadedFile::move` with a
   `getClientOriginalExtension()` name into a served directory yields `file_upload_candidate`; a
   `guessExtension()` allow-list sibling is guarded. A stored field compiled by `createTemplate`
   yields a stored `template_injection_candidate`; a constant template is none.
9. **AC9 (sample, offline).** `ZAZZLES_VULN_SYMFONY=<checkout> go test ./internal/pipeline -run TestSymfonySourceKey`
   passes at `086f81f`: 31 route entries, every required positive has a witnessed candidate at its
   anchor under its entry, `SYM-CMD-02` has a candidate with its stored link, and every control
   has its expected structural outcome. The checkout is clean before and after.
10. **AC10 (isolation and determinism).** `TestArchitectureBaseline` is unchanged for every
    pre-existing fixture. `TestDVWASourceKey` passes. Two scans of the Symfony fixtures and of the
    sample are byte-identical.
11. **AC11 (live).** One judged scan of the sample under the AGENTS.md standing terms, after the
    owner's word. Expected: all nine required positives are findings, `SYM-CMD-02` is Review or
    Confirmed, and no control is a finding. Every differing status is source-reviewed in
    `symfony-results.md`. The report is published as D-22 states. The README gains a
    `vuln-symfony` row from `accuracy.py` output.
12. **AC12 (docs and gate).** `docs/symfony-support.md` states the supported subset and every §4
    exclusion. The capability checklist is updated. The
    [contributor gate](../../docs/contributing.md#verification) passes.

## 8. Test strategy

One table-driven test per AC group over minimal synthetic projects under
`internal/langphp/testdata/symfony/`:

- `routes-attribute/`, `routes-annotation/`, `routes-yaml/` (with missing-controller and
  not-imported cases), `mixed-plain-php/`;
- `inputs/`; `services/` (promotion, interface alias, configuration flag);
- `doctrine-dbal/`, `doctrine-orm/`, `doctrine-storage/`;
- `twig/` (escaped, raw, autoescape off, script context, include, loop, `is_safe`, unknown filter);
- `response/`, `process/`, `url-open/`, `upload/`, `template-string/`.

Each vulnerable case has a protected and an unresolved sibling. Expected anchors are hand-computed.
A `walk` unit test covers `Config` and `Templates` selection. A YAML reader test covers flow style,
anchors, oversize files and symlinks. The sample is checked only by `TestSymfonySourceKey` and
`check.py`. Nothing tests Symfony features in the §4 exclusions.

## 9. Execution sequence

| Slice | Content | Depends on | ACs |
|---|---|---|---|
| **S0** | Detection guide, catalog row, frozen key rows, offline baseline | None | AC1 |
| **S1** | Project detection, document-root entries, YAML reader, attribute, annotation and YAML routes, controller resolution | S0 | AC2, AC3 |
| **S2** | Argument binding and `Request` sources; autowired services through W3 | S1, gaps W3 | AC4 |
| **S3** | Doctrine DBAL and ORM SQL | S2 | AC5 |
| **S4** | `Response`, Twig, entity storage keys, stored links | S2 | AC6 |
| **S5** | Service-side command and path, `Process`, URL-open SSRF, `filter_var` contracts | S2 | AC7 |
| **S6** | Upload and template injection on Symfony APIs | S4, gaps W5 and W6 | AC8 |
| **S7** | Sample key test, determinism, live run, sample publication, docs | All | AC9–AC12 |

S1 starts with the AC2 fixture failing. S3, S4 and S5 are independent once S2 lands and may be
assigned to separate Contributor Agents that own disjoint files. Skeleton for S1 and S2:

```go
type symfonyProject struct {
	root, docRoot string              // project dir and document root, relative to the scan root
	routing       []symfonyRouteImport // from config/routes*.yaml
	params        map[string]phpLiteral
	unread        []analysis.Gap       // symfony_config_unread
}
type symfonyRoute struct {
	methods    []string
	path, name string
	controller string            // FQCN::method
	origin     analysis.Evidence // attribute, docblock or YAML node
	mechanism  string            // attribute_route | annotation_route | config_route
}
func (s *phpSet) symfonyProjects() []*symfonyProject
func (p *symfonyProject) routes(s *phpSet) ([]symfonyRoute, []analysis.Gap)
func (f *phpFlow) bindActionArguments(route symfonyRoute, method *phpBoundCallable) []phpValue
```

## 10. Definition of done

- [ ] OQ-1 and OQ-4 answered and logged.
- [ ] The published sample carries the upstream license file and credit (D-22).
- [ ] AC1–AC12 verified, with evidence in the run log.
- [ ] The sample report shows route entries with controller methods, and no `FILE /src/…` entry.
- [ ] `git diff origin/stage --stat` matches §4.
- [ ] A fresh-context verifier reran `TestSymfonySourceKey`, checked three protected siblings and
      confirmed no pre-existing digest changed.

## 11. Open questions

- **OQ-1. Worktree.** Implement here after the gaps work, or in a separate `php-symfony` worktree
  cut from `stage` once gaps W3 merges? Recommendation: separate worktree. S0 can start at once,
  and S1 needs nothing from the gaps branch.
- **OQ-2. YAML dependency. Answered 2026-11-19: approved.** The owner approved
  `gopkg.in/yaml.v3`. Phase 6 asked the same as its OQ-1, and phase 9 reuses it.
- **OQ-3. Sample publication. Answered 2026-11-19:** publish it like the other samples. See D-22.
- **OQ-4. Review-expected stored command.** Is Review acceptable for `SYM-CMD-02` in this
  delivery? Confirming it needs the upload-extension writer and the wildcard writer linked to a
  command operand, which is the deepest stored chain in the key.
- **OQ-5. Deserialization. Answered 2026-11-19.** The owner asked for a separate contract:
  [unsafe deserialization](unsafe-deserialization.md), on its own branch and worktree.

## 12. Run log protocol

Use the plan's run-log rules. Record the OQ answers verbatim, sample pin and clean status before
and after each run, the fixture matrix, per-slice failing-first evidence, golden deltas, and live
run identifiers with request counts.

## 13. Agent implementation prompt

> Work in the owner-assigned sibling worktree. Read AGENTS.md, the orientation contents, this spec,
> the gaps contract's W3, W5 and W6, and the phase 6 decisions this spec keeps. Ask OQ-1 and OQ-4
> first. Deliver S0, then S1 from a failing AC2 fixture. Do not start S2 until gaps W3 is merged
> into your base. Run S3, S4 and S5 with disjoint file ownership if you delegate. Treat the sample
> as read-only data and keep it out of fixtures, detectors and requests. Make no paid call before
> the owner authorizes AC11. Finish each slice group as a draft PR into `stage` with its AC
> evidence. Verifier: a fresh-context subagent runs the `langphp` tests, `TestArchitectureBaseline`,
> `TestDVWASourceKey` and `TestSymfonySourceKey`, checks that each vulnerable fixture's protected
> sibling is not a finding and that unresolved routes appear in the JSON, and reports PASS or FAIL.

## 14. Implementation and review change log

### 2026-11-19 — Drafted

Written from a full source read of `vuln-symfony` at `086f81f`, an offline scan of it with the
scanner at `58e94e7`, and the PHP adapter code. Phase 6's scope is replaced: routes, inputs, DBAL
and ORM, and Twig remain; added are document-root entry selection, source-first resolution,
argument binding, entity storage keys, services, URL-open SSRF, guard contracts and a pinned
sample key. No code changed.

### 2026-11-19 — Owner answers

The owner approved `gopkg.in/yaml.v3` (OQ-2), so D-20 names it and S1 no longer waits. The owner
asked for a separate [deserialization contract](unsafe-deserialization.md) (OQ-5). D-16 gains Twig
service globals, which make the sample's `unserialize` call reachable.
The owner also chose to publish the sample report with attribution (OQ-3), recorded as D-22.
