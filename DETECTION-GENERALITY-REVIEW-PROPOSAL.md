# Proposal: review Code Scan for generality and use of the decision model

**2026-11-24. Proposed, not started.** To be assigned after the hardening lane
([branch 1](.zazz/specifications/juiceshop-nextjs-hardening-1.md),
[2](.zazz/specifications/juiceshop-nextjs-hardening-2.md),
[3](.zazz/specifications/juiceshop-nextjs-hardening-3.md)) is merged. The output of this work is a
written review with a ranked list of changes. It changes no scanner code.

## Why

Each analyzer family reaches a new application through adapters written by hand: an entry
adapter per framework, a storage adapter per driver, a contract per library. The hardening lane
showed the cost. Extending five families to Express with Sequelize took eight slices, and a
test on four applications that were not used for development recorded three new records in
total:

| Application | Stack | New records from the lane | What was missed |
|---|---|---:|---|
| oss-oopssec-store | Next.js, Prisma | 0 | Documented broken access control: no access facts outside Express |
| vuln-demo-app | Express, raw SQL | 0 | A missing admin check: the authorization rule reads Sequelize and Mongo operations only |
| vulnerable-typescript-app | Express, in-memory data | 2 | Mass assignment by object spread into an array: no ORM, so no rule |
| nodejs-goof | Express, Mongoose | 1 | The one record is a likely false positive: `app.get('env')` is not read as an environment guard |

The rules are general in that none names a sample. They are narrow in that each recognizes a
short list of libraries. Frameworks, storage drivers and message transports (queues, event
buses, webhooks, scheduled jobs) will keep arriving faster than adapters can be written one at
a time.

## The owner's aim

Most security scanners need explicit code for every framework, validation library and database
driver they support, and fall behind as new ones appear. Code Scan has a decision model in the
loop. The aim is to move library-specific recognition to that model wherever it can be done
safely, so that support does not have to be added one library at a time. The test of success is
a claim that holds across libraries without new code: SQL injection should be found for any SQL
database and driver, not only the ones with a written contract.

SQL injection shows what is and is not library-specific. That a string built from request data
reaches a call is a fact about the program, and the scanner can establish it for any language
construct. That the call sends the string to a database as SQL, and whether the driver binds
the values it is given, is knowledge about one library. Today that knowledge is a contract per
driver. It is the kind of thing a model knows, and its answer can be checked: the scanner
already holds the construction of the string and the arguments of the call.

## Question

Where can the scanner record less framework-specific structure and let the decision model
judge more, without losing the accuracy it has now?

The scanner's current division of work is deliberate: deterministic code establishes facts and
witnesses, the model answers bounded questions about them, and a policy checks the answers
against the facts. The review must keep what that buys: findings that cite source, replayable
requests, and a Protected verdict that means something. It should not propose "send the file to
the model".

## What the review should produce

1. **A map of where framework knowledge lives.** For each language adapter: which facts are
   read from a closed list (entries, request inputs, authentication middleware, ORM operations,
   sanitizers, sinks), how long each list is, and which lists the hardening lane had to extend.
2. **A classification of each list** as one of:
   - *Contract*: correctness depends on the library's documented behavior (a parameterized
     query, an escaping function). Stays deterministic.
   - *Recognition*: the list only decides whether a construct is noticed at all (is this call
     an authentication check, is this object a model). A candidate for model-assisted
     resolution with a deterministic check of the answer.
   - *Shape*: the list encodes one code shape of a general idea (a state change selected by a
     request value). A candidate for a language-level rule that needs no library name.
3. **Evidence from the existing mechanisms.** The scanner already has model-assisted route
   discovery (`--discover-routes`) and model-assisted evidence resolution. What did each cost
   and deliver, and what stopped them being used more widely?
4. **Three to five concrete proposals**, each with the facts it would generalize, the question
   the model would answer, how the answer is verified against source, the request and token
   cost, and the risk to exact replay.
5. **An accuracy guard for every proposal.** Which keyed rows and controls must not move, and a
   held-out application that the proposal is measured on before it is accepted.
6. **A ranked order**, with the first proposal small enough to be one branch.

## Candidates to examine first

These come from the lane and the held-out test. They are starting points, not conclusions.

| Candidate | Observation |
|---|---|
| Authentication and access on an entry | Three libraries are recognized. An application's own middleware is "unresolved". The model could be asked what a middleware on the chain requires of the caller, given its source, with the answer recorded as a fact and cited |
| SQL injection for any SQL driver | A written contract per driver says which call executes SQL and how it binds parameters. A call that receives a request-built string and has no contract is not a candidate at all. The scanner could record such calls as unresolved operations and ask the model what the callee does with its arguments, given the import and the call, then apply the existing SQL policy to the answer |
| "A state change on a record the request selects" | Written once per ORM. Raw SQL has the same shape in its `WHERE` clause, and PHP already reads it there. An in-memory collection has it too |
| "A whole request bag written to a stored object" | Recognized for ORM calls only. Object spread and `Object.assign` into any object that is later stored is the same claim |
| Entries beyond HTTP | Queue consumers, scheduled jobs, webhooks and event handlers receive untrusted input and have no entry adapter. What is the smallest common entry model that covers them |
| Outbound and storage drivers | Each new driver needs a contract before any family sees its operations. Which facts about a driver call can be established from its types or its documentation by the model, and checked |
| Environment and deployment guards | `process.env.NODE_ENV` is read and Express's `app.get('env')` was not. Guard recognition by enumeration will always trail |

## Method

- Read [technical approach](docs/technical-approach.md), the
  [architecture](.zazz/architecture/README.md) and
  [evidence and claims](.zazz/architecture/evidence-and-claims.md) before any code.
- Measure before proposing: count the closed lists and their entries per adapter from source.
- Use the applications under `<DEV_ROOT>` as held-out tests. At least one must not be Express
  with an ORM.
- Offline first. A paid run needs the owner's word, a stated question and a request cap.
- Write the review to `.zazz/evaluation/` and the ranked proposals to `.zazz/project/`. Do not
  open an implementation branch.

## Out of scope

Implementing any proposal. A new analyzer family. Replacing the policy check of model answers.
Changing the report schema.

## Constraints that must survive any proposal

- A finding cites the source facts it rests on.
- A Protected verdict is given only for a control the scanner has evidence of.
- Requests replay exactly from saved evidence.
- No rule names an application's own identifiers.
- No automatic provider or model fallback.
