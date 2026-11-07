# Goof URL-ID lookup: scoped NoSQL follow-up

[Contract](../specifications/command-injection.md#accepted-follow-up-express-path-ids-and-mongoose-findbyid) ·
[Analysis rules](../../docs/analysis/database-injection.md#bounded-express-and-mongoose-context) ·
[Sample](../../docs/samples/nodejs-goof/README.md) · [Metadata](../../docs/samples/nodejs-goof/metadata.json)

The user requested resolving Goof's `POST /update/:id` NoSQL Review from source semantics rather than
manually changing a saved answer. Scope includes the identical `GET /destroy/:id` lookup. The target
remained read-only and clean at `add14ba59e98240d9e00a235dd7d42cd61ae9912`.

## Source basis and mechanism

Both calls pass `req.params.id` directly to `Todo.findById` (`routes/index.js:232` and `:204`).
The literal Todo schema has the default ObjectId `_id`; the manifest pins Mongoose 4.2.4.
Express 4.12.4 assigns a decoded regex-capture string to the named URL parameter. Mongoose implements
`findById(id)` as `findOne({_id:id})`, with ObjectId casting or a cast error, without parsing string
contents into query operators. This differs from object-valued selector inputs such as Goof's login.

Primary implementation references:

- [Express parameter decoding](https://github.com/expressjs/express/blob/4.12.4/lib/router/layer.js#L136).
- [Mongoose findById](https://github.com/Automattic/mongoose/blob/4.2.4/lib/model.js#L1179).
- [Mongoose ObjectId casting](https://github.com/Automattic/mongoose/blob/4.2.4/lib/schema/objectid.js#L79).

The parser selects `mongoose-path-id-objectid-v1` only for this bounded source shape. The catalog
component carries operation semantics and requires source-backed `selector_path_string` evidence.
Normal NoSQL questions, completeness gates and all-path checks decide the result. A vulnerability
answer contradicting the scalar witness remains Review. The extractor never supplies a verdict.

Unknown middleware, `app.param`, request writes/escapes or unmodeled request methods, custom ID/schema
behavior, schema options and missing dependency pins do not qualify. Body/query objects and other
operations retain their existing contracts. Protection says nothing about authorization, ownership,
valid-ID error handling, business validation or stored-content rendering.

## Judgments and provenance

The user approved at most two OpenAI Decisions `gpt-6-luna` calls. Both completed without retries or
fallback. All other 32 Goof requests matched the prior full run and replayed exactly.

| Claim | Previous status | Fresh status | Input tokens |
| --- | --- | --- | ---: |
| GET /destroy/:id → findById | Review | Protected for NoSQL injection | 12,417 |
| POST /update/:id → findById | Review | Protected for NoSQL injection | 12,430 |

Total fresh usage: 2 requests, 24,847 input tokens. Both answered injection protection `protected`,
all paths protected `yes`, and all four coverage questions `yes`. These are static judgments, not
runtime exploitation or independent Findings Review. The current sample has 34 records:
4 Findings, 27 Review and 3 Protected. The command finding remains confirmed.

Retained evidence under `<DEV_ROOT>/zazzcode/zazzles/_test-findings/command-injection/findbyid-followup-20261107/`:
`ledger.json`, `source-manifest.json`, `final-source-manifest.json`, exact `traces/`, initial assessed
`nodejs-goof/run-1204339142/` and final offline-rendered `rendered/nodejs-goof/run-3132504896/`.
The original pass4 artifacts remain unchanged. The later display correction and conservative
request-method exclusion do not change these two requests; exact replay checks the final source.
This is not a new full paid scan and does not reassess other apps or analyzers.

## Verification

`TestMongoosePathIDFacts` covers source facts and exclusions. `TestMongoosePathIDJudgment` covers
protection, unsafe object selectors, contradictory/unknown answers, missing evidence, replay and
JSON/HTML/SARIF parity. Existing request baselines remain unchanged. Full `go test ./...`,
`go test -race ./...`, `go vet ./...` and `go build ./...` passed; affected tests were rerun after
final parser and protected-description changes. All 34 follow-up judgments replay against fresh
final-source analysis, with zero mismatches and no network.
