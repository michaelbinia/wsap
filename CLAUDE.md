# CLAUDE.md — Development Guidelines

Guidelines for AI coding assistants working on this repository.

## Scope of allowed changes

✓ Java source, tests, configs, Flyway migrations, docs
✓ New endpoints, services, repositories within the established layout
  (`controller/ service/ repository/ repository/jdbc/ model/ model/enums/
  service/enrichment/ service/enrichment/rules/ config/`)
✓ Refactoring within a package to improve clarity
✓ Adding dependencies that are well-known, actively maintained, and
  Apache 2.0 / MIT / EPL / BSD licensed
✓ SQL migration files — add new `V{n+1}__name.sql` only; never modify a
  committed migration
✓ Tooling scripts under `scripts/` (Python 3.10+, stdlib only — the
  data generator at `scripts/generate.py` is tooling, not product;
  it never ships inside the Java jar)

## Do not

✗ Introduce frameworks not already in `pom.xml` without prior discussion
✗ Add R2DBC, Reactor, WebFlux, or any reactive library — synchronous
  Spring MVC is the design
✗ Add JPA, Hibernate, or Spring Data JDBC — persistence is `JdbcClient`
  with hand-written SQL
✗ Add an ORM, a code-generation tool, or an aggregation DSL — plain SQL
  only
✗ Put persistence framework annotations on the domain records
  (`SecurityEvent`, `Rule`, `GeoLocation`) — the domain stays
  framework-free. Jackson and Jakarta Validation annotations are allowed
  ONLY on `*Dto` records
✗ Set `spring.jpa.hibernate.ddl-auto` — Flyway owns the schema
✗ Commit code that does not compile (`./mvnw compile` must pass before
  every commit)
✗ Commit tests that do not assert behaviour (`assertTrue(true)`,
  commented-out assertions)
✗ Reformat existing code unless explicitly asked
✗ Squash commit history before pushing
✗ Inline magic strings — route paths, SQL identifiers used in more than
  one place, index names, and header names go in
  `private static final` constants at the top of the relevant class
✗ Catch and swallow exceptions silently — log at WARN minimum,
  wrap-and-rethrow when the current layer is not the right handler
✗ Add license headers in source files — `pom.xml` carries the licence
✗ Add a Java data-generator package or a Spring profile for data
  generation — the generator is Python tooling in `scripts/`, not
  product code in the jar
✗ Pull in third-party Python dependencies for `scripts/` — stdlib only
  (`urllib.request`, `json`, `random`, `argparse`, `datetime`, `uuid`),
  so a fresh clone can run the script without `pip install`

## Coding conventions

- **Java 21.** Use records for DTOs and domain types. Pattern matching
  where it improves readability over `instanceof` chains. Exhaustive
  `switch` expressions on enums (lets the compiler enforce completeness).
- **One public class per file.** Package-private by default; promote to
  `public` only when crossing package boundaries.
- **Constants at the top of the file** for any string that appears in
  more than one place or has external meaning (route paths, SQL column
  names used from Java, header names).
- **No `Optional` in record field types** — use nullable references.
  `Optional` belongs in return types of query methods only.
- **No `static` mutable state** anywhere outside `*Test` classes.
- **`@Transactional`** on service classes or persistence facades only —
  never on controllers.
- **Persistence via `JdbcClient`.** All SQL lives in the
  `repository/jdbc/` adapter package. The service layer depends on the
  `SecurityEventRepository` port, not on any Jdbc type. Avoid
  database-specific SQL unless there's a reason; isolate vendor-specific
  snippets in a single adapter method with a comment explaining why.
- **PDF-defined names are exact** — `attackType` (not
  `attackCategory`), `receivedAt` (not `serverTimestamp`),
  `rule.category`, `rule.severity`, and the seven `AttackCategory` enum
  values match the assignment PDF.
- **Threat score invariants.** Severity CRITICAL=40, HIGH=30, MEDIUM=20,
  LOW=10. Action DENY=20, ALERT=10, MONITOR=0. Path contains `/admin` or
  `/login` → +15. More than 5 events from this `clientIp` in last 10
  minutes → +15 (strict `>` 5, excludes the event being scored). Cap at
  100. *These are the defaults bound by `MiniWsaProperties` from
  `application.yml` under `mini-wsa.*`; changing a default is a semantic
  change to the system and requires discussion.*
- **Repeat-offender count.** Measured on `received_at` (the
  server-stamped wall-clock instant), **not** on the client-supplied
  `timestamp` — the latter is trivially forgeable. The window has both
  bounds (`now - 10m, now`) and excludes the event currently being
  scored. Client-supplied `timestamp` values are still used for
  user-facing time ranges in the samples and stats endpoints, but
  never for scoring.
- **`attackType` is derived from `rule.category`,** never from
  `threatScore`.
- **Writes are idempotent on `event_id`.** The schema has
  `UNIQUE (event_id)` and inserts use `ON CONFLICT (event_id) DO
  NOTHING`. Re-ingesting the same event must not duplicate rows.
- **Replay semantics.** On duplicate `event_id` the ingest endpoint
  returns the **originally-stored row** with `status: DUPLICATE`. It
  does **not** return freshly computed enrichment values. The first
  write wins; a replay reflects what is actually in storage, not what
  a fresh scoring pass would produce now.
- **Validation errors are structured.** 400 responses include
  `fieldErrors[]` with the offending field path and, for batch requests,
  the event index.

## Test conventions

- **Naming:** `methodOrBehavior_underCondition_expectedResult` — e.g.
  `critical_deny_on_login_caps_at_100`.
- **Assertions:** `org.assertj.core.api.Assertions` only — readable,
  chainable, great failure messages.
- **One concept per test.** Multiple assertions are fine if they verify
  one behaviour; unrelated behaviours go in separate tests.
- **Unit tests** live under
  `src/test/java/com/security/wsa/service/enrichment/` and
  `src/test/java/com/security/wsa/service/` — plain JUnit 5, no Spring
  context. Mockito only for the repository port.
- **Integration tests** live under
  `src/test/java/com/security/wsa/repository/jdbc/` and
  `src/test/java/com/security/wsa/` — `@SpringBootTest` +
  `@Testcontainers` + `PostgreSQLContainer<>("postgres:16")`. No H2
  stand-ins.
- **Reset state in `@BeforeEach`** with
  `jdbc.sql("DELETE FROM security_events").update()`. Do not drop the
  table — Flyway runs once per container.
- **Assert observable behaviour** — not that a method called another
  method.

## Commit conventions

- **Small, logical commits.** One feature or fix per commit.
- **Conventional Commits** — `feat:`, `fix:`, `test:`, `docs:`,
  `chore:`, `refactor:`.
- **Imperative subject line, ≤ 72 chars.** "Add stats summary endpoint",
  not "Added" or "Adding".
- **Don't squash before pushing.**

## Decisions requiring discussion before implementation

- Architectural changes (storage engine, framework, blocking →
  reactive)
- New microservices or modules
- Major library upgrades (Spring Boot major version, Java major version)
- Deleting any test
- Changes to the REST API contract (request/response shapes, status
  codes, URL paths)
- Changes to the DB schema beyond additive migrations
- Fixing items listed in the README's "Known limitations" section.
  They are deliberately deferred; don't fix them opportunistically as
  part of unrelated changes.

## Build and run reference

```bash
# Compile only
./mvnw compile

# Run all tests (unit + Testcontainers integration)
./mvnw verify

# Generate and POST demo events to a running app (stdlib Python 3.10+)
python3 scripts/generate.py \
  --count 10000 --waves 10 --wave-size 50 \
  --target http://localhost:8080/v1/events/ingest

# Or write events as NDJSON (one JSON array per line) for later ingestion
python3 scripts/generate.py --count 10000 --output events.ndjson
```

## Security

- **No secrets in source or git history.** Use environment variables
  only. Default values in `application.yml` are for local development.
- **No real PII in sample data or tests.** The data generator and
  integration tests use RFC 5737 documentation IP ranges
  (`203.0.113.0/24`, `198.51.100.0/24`, `192.0.2.0/24`).
- **No production credentials** anywhere — this is a demo system.
- **SQL is parameterised.** Never build SQL by string concatenation of
  caller-supplied values; use `JdbcClient` named parameters
  (`:paramName`).

## Definition of done

A change is complete when:

1. `./mvnw verify` passes locally (unit + Testcontainers integration).
2. Changes are committed with a clear Conventional Commit message.
