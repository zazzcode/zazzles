# Architecture phase 6 — Symfony registration resolver

**Superseded (2026-11-19):** [PHP Symfony support](php-symfony-support.md) replaces this scope and
keeps D-3 to D-6. This document stays as history.

**Worktree / branch:** `php-symfony`
**Plan:** [architecture update plan](architecture-update-plan.md), phase 6. Objective: new feature on the foundation
**Depends on:** phases 0–3 merged (`internal/langphp`, the core API, and the graph classification table)
**Delivery topology:** one deliverable, one branch, one draft PR into `stage`
**Coordination:** Lead Agent. One Contributor Agent may own the routing-config reader (§9 step 2) and its tests
**Run log:** `.zazz/ephemeral/architecture-phase-6-symfony-run-log.md`
**Drafted:** 2026-11-17

## 1. Capability

Inside `internal/langphp`, add a Symfony registration resolver on top of the existing PHP flow. It
turns controller routes into source-backed HTTP entries that dispatch to PHP callables. Routes come
from three sources:

- PHP 8 `#[Route]` attributes, including a class-level prefix;
- `@Route` docblock annotations;
- `config/routes.yaml` and `config/routes/*.yaml`.

On those entries:

- **Inputs.** `Symfony\Component\HttpFoundation\Request` accessors become PHP input facts, and
  `{param}` placeholders bind to action arguments.
- **SQL.** Doctrine DBAL and ORM query construction reuses the SQL claim, with string text kept
  separate from bound parameters.
- **XSS.** `new Response($html)` and `$this->render()` with Twig templates reuse the XSS claim.
  The Twig output check is a bounded lexical scan.

A route that cannot be resolved stays visible as `resolution=unresolved`, and so does one with an
unresolvable controller. Neither is dropped. Plain-PHP behavior (DVWA) is unchanged.

## 2. Required reading

- Plan [shared rules](architecture-update-plan.md#shared-rules-for-every-phase), and phase 1 spec D-5 and D-7 (relations, mechanism table).
- [Phase 3 spec](architecture-phase-3-php-package.md) §9 and `internal/parse/core_api.go` (language core API).
- [PHP support contract](php-support.md) D-2 to D-7 (server-mapped entries, input facts, SQL, XSS models), [PHP results](../evaluation/php-support-results.md).
- [Architecture: shared, language and framework layers](../architecture/README.md#shared-language-and-framework-layers), [entry/dispatch](../architecture/README.md#multiple-entry-and-dispatch-mechanisms).
- Analysis rules: [database injection](../../docs/analysis/database-injection.md), [XSS](../../docs/analysis/xss.md), [input validation](../../docs/analysis/input-validation.md).
- Python Jinja precedent for lexical template output: `internal/langpy/templates.go` (`safe` filter handling).
- Container-root `repository-code-organization-review-proposal.md`, "Per planned extension", the Symfony row (requirements only).

## 3. Invariants

- `TestArchitectureBaseline` digests for every existing fixture are unchanged, including all PHP
  fixtures and `mixed/three-language`. New Symfony fixtures are the only additions.
- Resolution is source-only. The resolver does not run `bin/console`, the container, Composer, or
  the cache, and does not read `var/cache`.
- An unresolvable controller (service ID, missing class or method, closure in config) gets a
  dispatch binding with a gap. No callable is fabricated.
- A Twig autoescaped `{{ x }}` is encoding evidence for HTML-text context only, never generic
  protection. `|raw`, `{% autoescape false %}`, and unknown filters or contexts are never Protected.
- Doctrine `setParameter`/parameter arrays bind values. SQL or DQL text built by concatenation
  stays the SQL text operand.

## 4. Scope and review shape

| Path | New / modified | Purpose |
|---|---|---|
| `internal/langphp/symfony_project.go` | new | Project detection (`composer.json` requires `symfony/framework-bundle`); PSR-4 map from `autoload.psr-4` |
| `internal/langphp/symfony_routes.go` | new | Attribute, annotation, and YAML routes → entries, registrations, dispatch |
| `internal/langphp/symfony_inputs.go` | new | `Request` accessors and route-argument binding → existing PHP input fact roles |
| `internal/langphp/symfony_doctrine.go` | new | DBAL `executeQuery`/`executeStatement`/`fetch*` and ORM `createQuery`, plus QueryBuilder `where`/`andWhere`/`orWhere` with `setParameter` |
| `internal/langphp/symfony_twig.go` | new | `render`/`renderView` template resolution under `templates/`, lexical output scan |
| `internal/langphp/*_test.go`, `internal/langphp/testdata/symfony/<case>/` | new | Paired fixtures (§8) |
| `internal/walk/walk.go`, `walk_test.go` | modified | `Result.Config []File` for routing config names (`routes.yaml`, `routes/*.yaml`, `*.routing.yml` reserved for phase 9). Not a language |
| `internal/analysis/entry_graph.go` | modified | Add `attribute_route`, `annotation_route`, and `config_route` to the static mechanism table |
| `internal/analysispacks`, `internal/guidelines` | modified only if a contract ID is needed | Doctrine and Twig contract identities (`php-doctrine-dbal-v1`, `php-doctrine-orm-v1`, `twig-output-v1`) |
| `go.mod`, `go.sum` | modified if OQ-1 is approved | YAML parser |
| `docs/php-support.md`, `docs/detection-capabilities.md`, `.zazz/project/implementation-plan.md` capability checklist, `.zazz/architecture/README.md` §3 | modified | Supported Symfony subset and limits |
| `.zazz/evaluation/symfony-results.md` | new | Fixture matrix; optional sample results under OQ-2 |

Out of scope:

- XML routes (warn with a gap when `config/routes.xml` exists);
- `#[MapRequestPayload]` and Validator constraint semantics;
- security attributes as protection (recorded as entry context only);
- event subscribers and kernel listeners as entries;
- full Twig grammar, macros, inheritance beyond `{% extends %}`/`{% include %}` file resolution;
- API Platform;
- Drupal (phase 9);
- paid calls.

Review shape: one PR.

## 5. Decisions

- **D-1 The resolver lives in `langphp` on the existing PHP flow.** That honors the "no duplicated
  analyzers" rule. Symfony adds registration, inputs, and two library models. It adds no new flow engine.
- **D-2 Config files come through `walk.Result.Config`, an explicit name allow-list.** The walk
  stays the single inventory (phase 2). YAML is not a language, so it must not appear in `ByLanguage`.
- **D-3 PSR-4 resolution maps controllers to files.** `App\Controller\X::m` resolves through
  `composer.json` to `src/Controller/X.php`, then to class `X`, then to method `m`.
  `__invoke` controllers and the `X` short form are supported. Anything else is an unresolved
  dispatch with a gap. A basename-similarity search is rejected because the repository graph
  design forbids it as a binding rule.
- **D-4 Twig is a lexical output scan, not a grammar.** It recognizes:
  - `{{ expr }}`, encoded under default autoescape;
  - `{{ expr|raw }}`, raw;
  - `{% autoescape false %}…{% endautoescape %}`, raw region;
  - variables mapped from the `render` context array keys.
  Anything else produces a gap. This mirrors the shipped Jinja `safe` handling and resolves the old
  plan's contradiction between "do not parse templates" and "raw versus escaped fixtures".
- **D-5 Origin and mechanism.** Attribute, annotation, and YAML routes are `static` registrations
  with mechanisms `attribute_route`, `annotation_route`, and `config_route`. `{id}` paths are
  `framework_pattern`. The front controller `public/index.php` keeps its existing
  `server_file_mapping` entry: removing it would change plain-PHP semantics.
- **D-6 Request inputs map to the existing PHP input fact roles.** `query`, `request` (body),
  `attributes` (path), `cookies`, `headers`, `files`, `getContent()` (raw body). This is
  transport-neutral reuse. If the fact schema cannot express a role without a version bump, halt (§6).

## 6. Agent implementation rules

Follow the plan's [common rules](architecture-update-plan.md#common-agent-implementation-rules).
Additional halts:

- A change to an existing PHP fixture digest.
- An input fact version bump is needed (D-6).
- OQ-1 is unanswered when YAML parsing starts. Attribute and annotation work may proceed first.

## 7. Acceptance criteria

1. **AC1 Attribute routes.** A controller with class `#[Route('/blog')]` and method
   `#[Route('/{slug}', methods: ['GET'])]` yields one `GET /blog/{slug}` entry. Its registration is
   `static`/`framework_pattern`/`resolved`, and it dispatches to the method callable.
2. **AC2 Annotation and YAML routes.** An `@Route` docblock and a `routes.yaml` entry with
   `controller: App\Controller\X::show` each yield a resolved entry. A YAML route whose controller
   class is missing yields an `unresolved` registration with a gap, and it stays in the report.
3. **AC3 Inputs.** `$request->query->get('q')` and an `{id}` action argument reach a SQL sink as
   request-origin input facts, with role and parameter recorded.
4. **AC4 Doctrine pairs.**
   - DBAL `executeQuery("… WHERE id = " . $id)` is a SQL candidate.
   - `executeQuery("… WHERE id = ?", [$id])` carries a bound-parameter witness and is not Confirmed.
   - QueryBuilder `->where("u.name = '" . $n . "'")` is a candidate.
   - `->where('u.name = :n')->setParameter('n', $n)` is bound.
   - An unknown receiver gives a gap.
5. **AC5 Output pairs.**
   - `new Response('<p>' . $q . '</p>')` is a raw XSS candidate.
   - Twig `{{ q }}` is encoded (HTML text).
   - `{{ q|raw }}` and an `autoescape false` region are raw candidates.
   - An unknown filter gives a gap.
6. **AC6 Isolation.** `TestArchitectureBaseline` is unchanged for every pre-existing fixture. A
   DVWA-style fixture has no Symfony entries.
7. **AC7 Determinism.** Two scans of the Symfony fixtures are byte-identical. Entries from
   attributes, annotations, and YAML do not depend on file walk order.
8. **AC8 Docs.** The supported subset and its explicit exclusions (§4) are documented in the user
   PHP doc and the capability checklist. The contributor gate passes.

## 8. Test strategy

There is one table-driven test per AC group, over the fixtures under
`internal/langphp/testdata/symfony/`:

- `routes-attribute/`;
- `routes-annotation/`;
- `routes-yaml/`, with a missing-controller case;
- `inputs/`;
- `doctrine/`, vulnerable, bound, and unknown;
- `twig/`, escaped, raw, autoescape-off, and unknown filter.

Fixtures are synthetic, minimal, and written for this phase. Each vulnerable case has a protected
sibling, and the expected anchors are hand-computed in the test. A walk unit test covers
`Config` selection. There are no tests for Symfony features out of scope.

## 9. TDD entry point and execution sequence

1. **Red:** the AC1 fixture and test.
2. Project detection and PSR-4 map; attribute and annotation routes (AC1, AC2 partly). The skeleton:

```go
type symfonyProject struct{ root string; psr4 map[string]string } // namespace prefix → dir
type symfonyRoute struct {
	methods []string; path string; name string
	controller string           // FQCN::method
	origin analysis.Evidence    // attribute/annotation/YAML node
	mechanism string            // attribute_route | annotation_route | config_route
}
func detectSymfony(inv parse.Inventory) (*symfonyProject, bool)
func (p *symfonyProject) routes(set *phpSet) ([]symfonyRoute, []analysis.Gap)
func (p *symfonyProject) resolveController(fqcn string) (*phpCallable, *analysis.Gap)
```

3. `walk.Result.Config`, then YAML routes after OQ-1 (AC2).
4. Inputs (AC3), Doctrine (AC4), Response and Twig (AC5).
5. Mechanism table, isolation and determinism (AC6, AC7), docs, gate, draft PR.

## 10. Definition of done

- [ ] Required reading done; standards lookup recorded.
- [ ] OQ-1 and OQ-2 answered and logged.
- [ ] AC1–AC8 verified, with evidence in the run log.
- [ ] `git diff origin/stage --stat` matches §4.

## 11. Open questions

- **OQ-1** Approve adding `gopkg.in/yaml.v3` (pure Go) for routing YAML? The alternative is a
  hand-written subset reader for `name: {path, controller, methods}` maps, which is fragile with
  anchors and flow style. Recommendation: approve. Phase 9 reuses it.
- **OQ-2** Pin `symfony/demo` (or another owner-chosen app) as an offline-only sample for
  `symfony-results.md`? Fixtures alone satisfy the ACs. A sample adds realism, but it needs a clone
  and a pin in the sample catalog. Recommendation: yes, offline only.

## 12. Run log protocol

Use the plan's common rules. Record the OQ answers verbatim, the fixture matrix, and the optional sample pin.

## 13. Agent implementation prompt

> Work in the `php-symfony` sibling worktree, cut from `origin/stage` after phase 3 merged. Read
> AGENTS.md, the orientation contents, the [plan](architecture-update-plan.md), and this spec, including
> the phase 1 and phase 3 specs it cites. Follow the plan's session start and common rules. Ask
> OQ-1 and OQ-2 first; attribute-route work may begin while waiting. Execute §9 TDD-first. You may
> delegate the YAML and `walk.Config` reader (§9 step 3) to one Contributor Agent that owns those
> files. Make no paid calls. Finish with a draft PR into `stage` listing AC1–AC8 evidence. Verifier:
> a fresh-context subagent runs the `langphp` tests and `TestArchitectureBaseline`. It confirms that no
> pre-existing fixture digest changed, and checks that each vulnerable fixture's protected sibling
> is not Confirmed and that unresolved routes appear in the JSON. It reports PASS or FAIL.

## 14. Implementation and review change log

### 2026-11-18 — Paths after architecture phase 3B

Source: [phase 3B](architecture-phase-3-js-ts-python-package.md) moved JS/TS to `internal/langjs` and
Python to `internal/langpy`; `internal/parse` is the language core. Changed: §2 required-reading path for the Jinja precedent. No scope change.
