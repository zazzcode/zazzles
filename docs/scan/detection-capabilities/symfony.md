# Symfony coverage

[Detection capabilities](../detection-capabilities.md) · [Symfony analysis](../symfony-support.md) · [Twig coverage](twig.md) · [PHP analysis](../php-support.md)

This page lists what Code Scan reads in a Symfony application: how an action is reached, which
request and stored values it tracks, and which framework calls are recorded as operations. Each
operation belongs to a vulnerability class, and that class page describes the claim and its
verdicts. [Twig output](twig.md) has its own page.

## Entries

| Form | Example | What the scanner establishes |
| --- | --- | --- |
| Route attribute on an action | `#[Route('/post/{slug}', methods: ['GET'])]` | One entry for each method and path pair |
| Route attribute on the class | `#[Route('/admin', methods: ['POST'])]` above the class | The path and name prefix every action. The methods apply to an action that declares none |
| Invokable controller | A class-level route and a public `__invoke` with no action route | The class route is the entry for `__invoke` |
| Docblock annotation | `@Route("/c", methods={"GET"})` with the annotation class imported | The same entry as an attribute |
| YAML route | `controller: App\Controller\X::show` in `config/routes.yaml` | The entry dispatches to the named public method, or to `__invoke` |
| Public PHP file | `public/info.php` | A file entry. Files outside the public directory are not entries. A file entry carries no access rule |

A route entry records `access`: whether a login is required and which roles, from
`access_control`, a `security: false` firewall, `#[IsGranted]` and a leading
`denyAccessUnlessGranted`. The first matching rule wins. That access is context for the
[authorization](missing-authorization.md) claim. It is not protection for any other
claim. The entry also lists `state_changes` for the stored writes its action performs.

A route that the routing configuration does not import, a non-literal path or method list, and a
controller that does not resolve to a public project method are recorded as entries with a
dispatch gap. They are not analyzed.

## Request values

| Form | Example | What the scanner establishes |
| --- | --- | --- |
| Parameter bags | `$request->query->get('q')`, `->request`, `->headers`, `->cookies`, `->attributes`, `->server`, `->files` | A named field with its origin |
| Typed bag readers | `getString('q')`, `getInt('n')`, `getDigits`, `getBoolean`, `getAlpha`, `getAlnum`, `getEnum` | The same field with a typed conversion. `getInt` and `getDigits` are numeric. `getBoolean` carries no content |
| Whole bag | `$request->query->all()`, `$request->request->all()` | Every field of that bag |
| Any-source read | `$request->get('q')` | A path, query or form field |
| Body | `getContent()`, `json_decode($request->getContent(), true)`, `toArray()`, `getPayload()` | The body and its decoded fields |
| Request line | `getUri()`, `getRequestUri()`, `getPathInfo()`, `getQueryString()`, `getHost()`, `getClientIp()` | A URL or header value |
| Route placeholder | `{slug}`, `{id<\d+>}`, `{page?1}`, `{slug}.html`, `{!page}` bound to an action argument | A path value. An `int`, `float` or `bool` argument and a digits-only inline requirement are numeric |
| Mapped argument | `#[MapQueryParameter] string $q`, `#[MapQueryString]`, `#[MapRequestPayload]` | A query field or the fields of the mapped object |
| PHP superglobals | `$_SERVER['HTTP_REFERER']`, `$_COOKIE['c']` inside a service | The same request value as in plain PHP |

## Services and stored values

| Form | Example | What the scanner establishes |
| --- | --- | --- |
| Typed service argument | `Analytics $analytics` on an action or constructor | The project class, with its methods followed to depth four |
| Configured argument | `$trackingEnabled: '%env(bool:TRACKING_ENABLED)%'` in `config/services.yaml` | A configuration condition on the path |
| Entity argument | `Post $post` on a route with a placeholder, `#[MapEntity]`, `#[CurrentUser] ?User $user`, `$this->getUser()` | A stored entity whose mapped string fields are stored reads |
| Entity field types | `private ?int $id`, `private bool $isAdmin` | An `int`, `float` or `bool` field holds no text. It is not rendering content |
| Doctrine finders and results | `findAll()`, `findBy([...])`, `findOneBy([...])`, `getResult()` | Stored entities of the repository's class |
| Associations | `$post->getAuthor()->getUsername()` | The related entity's field |
| Stored writes | `$user->setAboutMe($x)` then `flush()`, `persist($entity)`, a loop that assigns `$this->$key = $value` | A writer of that field. A dynamic property write is a writer of every mapped field |
| Flash messages | `$this->addFlash('error', $text)` and `app.flashes('error')` | A session store keyed by the flash type. A type with only literal messages, or with no writer, carries no request value |

A stored read is linked to the request that wrote it. When no writer is linked, the record stays
in Review with `storage_origin_unresolved`.

## Operations

| Class | Symfony and PHP forms recorded | Notes |
| --- | --- | --- |
| [SQL injection](sql-injection.md) | DBAL `executeQuery`, `executeStatement`, `fetch*`, `prepare`; ORM `createQuery`, `createNativeQuery`; QueryBuilder `select`, `from`, `where`, `andWhere`, `orWhere`, `having`, `orderBy`, `groupBy`, `set`, `join` condition, `add` | Query text and bound values are separate slots. A chain keeps its text through `setParameter`, `setMaxResults`, `setFirstResult` and the other setters that add no text |
| [Cross-site scripting](cross-site-scripting.md) | `new Response($html)`, `Response::setContent`, and [Twig output](twig.md) | A literal non-HTML `Content-Type` removes the claim. `JsonResponse` and `json()` are not HTML |
| [Command](command-injection.md) and [argument injection](argument-injection.md) | `shell_exec`, `exec`, `system`, `passthru`, `popen`, `proc_open`, backtick commands, `Process::fromShellCommandline`, `new Process([...])` | Shell text and an argument vector carry different evidence |
| [Path traversal](path-traversal.md) | PHP file functions, `include` and `require`, `BinaryFileResponse`, the controller `file()` helper | The operand keeps its literal base directory |
| [File upload](file-upload.md) | `UploadedFile::move($directory, $name)` | Records the destination, whether it is served, and where the stored extension comes from |
| [SSRF](server-side-request-forgery.md) | `file_get_contents` and other URL-capable PHP functions, cURL, Symfony HttpClient `request` | A value that starts with a literal local path is not a URL operand |
| [Template injection](template-injection.md) | `Environment::createTemplate`, `template_from_string`, a project Twig function that compiles its argument | Followed from the template call into the PHP callable |
| [Code injection](code-injection.md) | `eval`, string `assert`, `create_function` | |
| [Unsafe deserialization](unsafe-deserialization.md) | `unserialize`, `Yaml::parse` with object support | Includes a service built as a Twig global, which runs on every rendered page |
| [Open redirect](open-redirect.md) | `redirect($url)`, `new RedirectResponse($url)`, `header('Location: ...')` | `redirectToRoute` takes a route name and is not recorded |
| [Sensitive data in logs](sensitive-data-logging.md) | PSR-3 logger methods and `error_log` | Requires a value with a sensitive-data source |
| [Information exposure](information-exposure.md) | `phpinfo()`, `debug_print_backtrace()`, dumps of environment arrays, `Response` bodies built from server state | No request source. Guards on the path are recorded for the decision model |
| [Mass assignment](mass-assignment.md) | A whole request bag iterated into `$entity->$key`, a `set…` dispatch or `PropertyAccessor::setValue` | Records the entity's credential, login identifier and role-source fields from the security contracts |
| [Missing authorization](missing-authorization.md) | A stored write, file write or delete, or a response that carries a census field of a request-selected or enumerated record | Records the subject, the operation, the entry's access and the guards that dominate the operation. An address check is its own guard kind |
| [Account enumeration](account-enumeration.md) | Doctrine finders on an account class, and the flash, redirect, render, `Response` and `JsonResponse` answers on each side of the result branch | The two response lists are compared with each other. Entries with access `required` are not recorded |
| [Weak password recovery](weak-password-recovery.md) | Symfony Mailer `Email` and `TemplatedEmail` recipients and content, `MailerInterface::send`, URL generation that carries a generated secret | Records the recipient's origin and the checks that covered it. Mail content is not a rendering sink |
| [Weak password hashing](weak-password-hashing.md) | A fast digest written to the security user's credential field, a `PasswordHasherInterface` class and `security.password_hashers` | A variable name never establishes a password |

## Recorded in Review

| Form | Example | Why it is in Review |
| --- | --- | --- |
| Unresolved service or receiver | A method call on a value with no declared type | The operation or its operand cannot be verified |
| Environment-dependent path | A service method that returns early on a configuration flag | The flag is evidence on the path. It is not a protection |
| Unlinked stored value | An entity field with no request writer in scanned source | The origin of the stored content is unknown |
| Loops and unsupported control flow | A collection built in a `foreach` | The loop body is modeled once |
| Form, serializer or payload mapping onto an entity | `$form->handleRequest($request)`, `deserialize(…, Entity::class, …)`, `#[MapRequestPayload]` | Recorded as mass assignment with a gap. Form types and serializer groups are not read |
| Framework dumps | `dump($value)`, `dd($value)` | Output depends on the debug environment |

## Not recorded

| Form | Example | Boundary |
| --- | --- | --- |
| Other route sources | XML or PHP route files, API Platform resources, console commands, Messenger handlers, event subscribers | Not discovered as entries |
| Forms and validation | Symfony Form types and Validator constraints | Not modeled as inputs or as controls |
| Filesystem component | `Filesystem::remove($path)` | Not a recorded path operation |
| Session attributes | `$request->getSession()->set()` and `->get()` | Not linked as a store |
| Mail bodies | HTML passed to `Email::html()` | Not a rendering sink. Mail content is a delivery sink for the recovery claim only |
| XML parsing | `simplexml_load_string` with entity loading | No XML external entity analyzer |

## Outside these claims

Committed secrets, voters and custom authenticators, Form and serializer mass assignment,
and the exclusions on each family page stay outside. A clean report says nothing about
them. Information exposure, mass assignment, missing authorization, account enumeration,
recovery-secret delivery, weak password hashing, insecure configuration and SSRF
(including a `curl` or `wget` shell URL) are the website claims. Entry access is recorded
for every route. Address trust is filled when the proxy configuration was readable.
