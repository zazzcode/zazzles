# Architecture phase 9 — Drupal registration resolver

**Worktree / branch:** `php-drupal`
**Plan:** [architecture update plan](architecture-update-plan.md), phase 9. Objective: new feature on the foundation
**Depends on:** phase 6 merged (Symfony config-to-callable helper, `walk.Result.Config`, YAML reader)
**Delivery topology:** one deliverable, one branch, one draft PR into `stage`
**Coordination:** Lead Agent alone
**Run log:** `.zazz/ephemeral/architecture-phase-9-drupal-run-log.md`
**Drafted:** 2026-11-17

## 1. Capability

Add a second registration resolver in `internal/langphp`, for Drupal 9, 10, and 11 modules:

- **Routes.** `*.routing.yml` routes become HTTP entries dispatching to `_controller` methods and
  `_form` classes (`buildForm`/`submitForm`/`validateForm`). Route `requirements` (`_permission`,
  `_role`, `_access`, `_custom_access`) are recorded as entry context.
- **Inputs.** Request and form inputs reuse the PHP input facts: the `Request` accessors from
  phase 6 plus `FormStateInterface::getValue()`/`getValues()`/`getUserInput()`.
- **Database API.** `\Drupal::database()` and injected `Connection` calls follow placeholder
  semantics: `query()` with `:name` placeholders and an argument array, plus `select()`/`condition()`.
  Concatenated query text is the SQL text operand.
- **Render output.** Render arrays (`#markup`, `#children`, `Markup::create()`) and Twig (phase 6
  scan) reuse the XSS claim.
- **Extensions.** Drupal's PHP-bearing extensions are scanned as PHP.

Symfony and plain-PHP results are unchanged.

## 2. Required reading

- [Phase 6 spec](architecture-phase-6-symfony.md) D-2 to D-6 and its delivered code (the resolver
  pattern to reuse, not import).
- [Phase 3 spec](architecture-phase-3-php-package.md) (core API), phase 1 D-7 (mechanism table).
- [Database injection rules](../../docs/scan/analysis/database-injection.md), [XSS rules](../../docs/scan/analysis/xss.md).
- `internal/lang/lang.go` (extension registry) and its tests.

## 3. Invariants

- `TestArchitectureBaseline` digests are unchanged for every pre-existing fixture, including the
  phase 6 Symfony fixtures. The Drupal resolver is not enabled for a Symfony project, and Symfony
  fixtures pass without it.
- The Drupal resolver shares the config-to-callable helper with Symfony through a neutral
  `langphp` file. Neither resolver imports or calls the other's framework-specific code.
- Access requirements are authorization context only. They are never injection or XSS protection.
- `#markup` is not treated as raw. Drupal filters it with an admin-level XSS filter, so it is
  recorded as filtered-HTML context, which is Review and never Protected. `Markup::create($x)` and
  `#children` are raw. These rules live in the analysis guide.
- No Drupal bootstrap, Drush, or database access. Source only.

## 4. Scope and review shape

| Path | New / modified | Purpose |
|---|---|---|
| `internal/langphp/config_callables.go` | new or moved from phase 6 code | Neutral `FQCN::method` and `_form` class resolution shared by both resolvers (pure move plus generalization) |
| `internal/langphp/drupal_project.go` | new | Detection: `*.info.yml` with `core_version_requirement`, or `composer.json` requiring `drupal/core*` |
| `internal/langphp/drupal_routes.go` | new | `*.routing.yml` → entries; mechanism `config_route`; requirements context |
| `internal/langphp/drupal_forms.go` | new | `_form` dispatch to `buildForm`/`submitForm`/`validateForm`; `FormStateInterface` inputs |
| `internal/langphp/drupal_database.go` | new | `query()` placeholders and arrays; `select()->condition()`; concatenation as text |
| `internal/langphp/drupal_render.go` | new | `#markup`, `#children`, `Markup::create`, `#theme` → Twig |
| `internal/langphp/*_test.go`, `internal/langphp/testdata/drupal/<case>/` | new | Paired fixtures (§8) |
| `internal/lang/lang.go`, `lang_test.go` | modified | `.module`, `.install`, `.theme`, `.profile`, `.engine` → PHP; `.inc` → PHP only when the file begins with `<?php` |
| `internal/walk/walk.go` | modified | `*.routing.yml` in `Config` (name reserved in phase 6) |
| `docs/php-support.md`, `docs/detection-capabilities.md`, `docs/analysis/xss.md`, `.zazz/project/implementation-plan.md`, `.zazz/architecture/README.md` §3 | modified | Supported Drupal subset, `#markup` rule, limits |
| `.zazz/evaluation/drupal-results.md` | new | Fixture matrix; optional sample under OQ-1 |

Out of scope:

- Drupal 7 (`hook_menu`, `db_query`);
- hooks as entries beyond form callbacks (recorded as a gap when `hook_*` functions receive request
  data, not modeled);
- event subscribers;
- the Entity API;
- Views;
- plugin annotations and attributes;
- Drupal services YAML for DI resolution beyond typed constructor arguments;
- paid calls.

Review shape: one PR.

## 5. Decisions

- **D-1 A shared helper, not a Drupal → Symfony dependency.** Drupal routes reuse the same callable
  resolution. A neutral file keeps the two framework resolvers independent, as the plan's
  container-root organization review asks.
- **D-2 `.inc` is content-gated.** `.inc` is common outside PHP. Requiring a leading `<?php` avoids
  parsing non-PHP files as PHP, which would produce parse-error gaps. The other Drupal extensions
  are unambiguous.
- **D-3 `#markup` is filtered-HTML context.** Treating it as raw would mass-report Drupal's normal
  pattern, while treating it as safe would hide admin-filter bypasses. Review with explicit context
  matches the evidence.
- **D-4 Access requirements are context, not protection.** They are authorization, which is a
  different question from injection protection.

## 6. Agent implementation rules

Follow the plan's [common rules](architecture-update-plan.md#common-agent-implementation-rules).
Additional halts:

- Any Symfony or plain-PHP fixture digest changes.
- The shared helper extraction changes Symfony behavior.
- A new extension mapping changes the language of a file in an existing fixture.

## 7. Acceptance criteria

1. **AC1 Routes.** A module with `example.routing.yml` (`path: '/example/{node}'`,
   `_controller: '\Drupal\example\Controller\X::view'`, `_permission: 'access content'`) yields a
   resolved `GET` entry with `static`/`framework_pattern`. The permission is attached as context.
   A route to a missing class is `unresolved` with a gap.
2. **AC2 Forms.** A `_form` route dispatches to `buildForm` and `submitForm`. A
   `$form_state->getValue('q')` reaching `query()` by concatenation is a SQL candidate.
3. **AC3 Database pairs.**
   - `query("… WHERE nid = " . $nid)` is a candidate.
   - `query("… WHERE nid = :nid", [':nid' => $nid])` is bound and not Confirmed.
   - `select('node','n')->condition('n.title', $t)` is bound.
   - An unknown receiver gives a gap.
4. **AC4 Render pairs.**
   - `Markup::create($q)` and `#children` are raw candidates.
   - `#markup` with request data is filtered-HTML context in Review, never Protected.
   - `#theme` with a Twig `{{ q }}` is encoded, and `{{ q|raw }}` is raw.
5. **AC5 Extensions.** `.module` hooks file is parsed as PHP. A `.inc` without `<?php` is not
   language PHP. The `internal/lang` table test covers both.
6. **AC6 Isolation.** `TestArchitectureBaseline` digests are unchanged for every pre-existing fixture.
   The Symfony fixtures produce no Drupal entries.
7. **AC7 Docs.** The supported subset, the D-3 rule, and exclusions are documented. The contributor gate passes.

## 8. Test strategy

Use table-driven tests over `internal/langphp/testdata/drupal/{routes,forms,database,render,extensions}/`.
Fixtures are synthetic, with each vulnerable case paired with a bound or escaped sibling and an
unresolved case. Reference anchors are hand-computed. Language detection is covered in the existing
`lang_test.go` table.

## 9. TDD entry point and execution sequence

1. **Red:** the AC1 routing fixture and test.
2. Extract `config_callables.go` from the phase 6 resolver as a pure move. The Symfony tests must stay green.
3. Detection and routes (AC1), then forms (AC2), the database API (AC3), and render (AC4). The skeleton:

```go
type drupalModule struct{ name, dir string; info analysis.Evidence }
func detectDrupal(inv parse.Inventory, cfg []walk.File) ([]drupalModule, bool)
func (m drupalModule) routes(set *phpSet, cfg []walk.File) ([]configRoute, []analysis.Gap) // configRoute shared with Symfony
```

4. Extensions (AC5), isolation (AC6), docs, gate, draft PR.

## 10. Definition of done

- [ ] Required reading done; standards lookup recorded.
- [ ] AC1–AC7 verified, with evidence in the run log.
- [ ] `git diff origin/stage --stat` matches §4.

## 11. Open questions

- **OQ-1** Pin a public Drupal module or site (owner's choice) as an offline-only sample for
  `drupal-results.md`? Fixtures alone satisfy the ACs. Recommendation: one small contrib module with
  a published SQL or XSS advisory, offline only.

## 12. Run log protocol

Use the plan's common rules. Record the OQ-1 answer verbatim and any sample pin.

## 13. Agent implementation prompt

> Work in the `php-drupal` sibling worktree, cut from `origin/stage` after phase 6 merged. Read
> AGENTS.md, the orientation contents, the [plan](architecture-update-plan.md), this spec, and the
> phase 6 spec. Follow the plan's session start and common rules. Ask OQ-1 first, then execute §9
> TDD-first. Keep step 2 a pure move. Make no paid calls. Finish with a draft PR into `stage` listing
> AC1–AC7 evidence. Verifier: a fresh-context subagent runs the `langphp` and `lang` tests and
> `TestArchitectureBaseline`. It confirms that the Symfony fixtures are unchanged and that no Drupal
> file imports Symfony-specific code, and it reports PASS or FAIL.

## 14. Implementation and review change log

No changes recorded.
