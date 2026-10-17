# Mini WSA — Mini Security Analytics Pipeline

A small, blocking Spring Boot service that ingests simulated security events
(DLRs), classifies and scores them, stores them in Postgres, and exposes
aggregated analytics plus a filtered sample feed. Backend take-home assignment
for the Akamai CSI group.

## Architecture

```
                                    +--------------------------+
client -> IngestionController ----> | IngestionService         |
                                    |  - ThreatScoreCalculator |---> SecurityEventRepository (port)
                                    |      (Strategy pattern:  |                     |
                                    |       Severity, Action,  |                     v
                                    |       SensitivePath,     |            JdbcSecurityEventRepository (adapter)
                                    |       RepeatOffender)    |                     |
                                    |  - AttackClassifier      |                     v
                                    +--------------------------+               JdbcClient + Postgres 16
                                                                                     |
client -> StatsController   -----> StatsService   ----> SecurityEventRepository -----+
client -> SamplesController -----> SamplesService ----> SecurityEventRepository -----+
```

- `model/` holds the domain records (`SecurityEvent`, `Rule`, `GeoLocation`)
  and the wire DTOs (`SecurityEventDto`, `RuleDto`, `GeoLocationDto`,
  `StatsSummaryResponse`, `SamplesResponse`, …). Domain records carry no
  framework imports.
- `repository/` declares the port interface. `repository/jdbc/` is the
  adapter — all SQL lives there.
- `service/enrichment/rules/` is the Strategy pattern collection used by
  `ThreatScoreCalculator`. Adding a new rule is a one-file change.
- `GlobalExceptionHandler` turns validation failures, bad enum values,
  malformed JSON, DB conflicts, and unexpected errors into structured
  JSON responses.

## Tech stack

- **Java 21** (records, exhaustive switch, pattern matching).
- **Spring Boot 3.4.x** on Spring MVC (blocking I/O).
- **PostgreSQL 16** accessed via Spring's `JdbcClient` — no JPA, no
  Hibernate, no Spring Data JDBC.
- **Flyway** owns the schema (`V1__init.sql`).
- **springdoc-openapi** + **Spring Boot Actuator** for live docs and
  health.
- **Testcontainers** `postgres:16` + **JUnit 5** + **Mockito** +
  **AssertJ** for tests. GitHub Actions runs unit + Testcontainers
  integration on every push and PR, plus CodeQL on a weekly cron.

### Configuration

All scoring weights, pagination limits, and the repeat-offender window
are externalised in `application.yml` under the `mini-wsa.*` prefix:

```yaml
mini-wsa:
  stats:
    top-n: 10
  samples:
    default-limit: 20
    max-limit: 100
  scoring:
    max-score: 100
    severity: { CRITICAL: 40, HIGH: 30, MEDIUM: 20, LOW: 10 }
    action:   { DENY: 20, ALERT: 10, MONITOR: 0 }
    sensitive-path:
      bonus: 15
      markers: [ /admin, /login ]
    repeat-offender:
      bonus: 15
      threshold: 5
      window: PT10M   # ISO-8601 duration
```

Defaults match the assignment PDF exactly. The application refuses to
start if the config is incomplete (every `Severity` and `Action` enum
value must appear in its weight map, `maxLimit >= defaultLimit`, etc.).
Override via environment variables using Spring's relaxed binding:
`MINI_WSA_SCORING_SEVERITY_CRITICAL=50`,
`MINI_WSA_SCORING_REPEAT_OFFENDER_WINDOW=PT5M`, and so on.

The `@Max(100)` safety ceiling on the samples `limit` query parameter
stays hard-coded as a compile-time guard — the YAML's `max-limit`
documents it rather than driving it, so a config bug can't silently
accept `limit=1_000_000`.

## Storage choice

**PostgreSQL 16 with hand-written SQL via `JdbcClient`.** Justification:

- The DLR is a flat log record after flattening the nested `rule.*` and
  `geoLocation.*` fields into columns, which maps cleanly to a single
  relational table (`V1__init.sql`).
- Every analytics endpoint reduces to a `GROUP BY` + `ORDER BY … LIMIT`
  query that any reviewer can read. No ORM, no DSL between the SQL and
  the user.
- `JdbcClient` is the smallest API Spring offers for parameterised SQL,
  which lets the domain `SecurityEvent` record stay annotation-free —
  the arrow of the Dependency Inversion Principle points inward.
- Flyway makes the schema a reviewable artefact rather than an inferred
  side-effect of code.
- `UNIQUE (event_id)` + `ON CONFLICT (event_id) DO NOTHING` make
  ingestion idempotent at the storage layer.

Trade-off vs. the real Akamai WSA, which runs on Elasticsearch:
Postgres loses native `date_histogram` and ergonomic full-text search
over `userAgent` / `path`, in exchange for strong consistency, lower
operational cost, and SQL I can defend line-by-line in an interview. At
real WSA scale (billions of DLRs/day) I would migrate the hot read path
to Elasticsearch and keep Postgres only as the system of record.

## Build and run

Prerequisites: Java 21 (Temurin) and Docker.

```bash
# Compile only
./mvnw compile

# Unit + Testcontainers integration tests (needs Docker)
./mvnw test

# Full build + run locally against a Postgres you provide
./mvnw spring-boot:run

# Bring up the whole stack
docker compose up --build

# Seed ~10 demo events into the running app (fires the repeat-offender
# bonus on the 7th burst event)
./scripts/seed-demo.sh
curl -s localhost:8080/v1/stats/summary | jq
```

## API

All endpoints produce and consume JSON. Interactive UI:
`http://localhost:8080/swagger-ui.html`. Raw OpenAPI:
`http://localhost:8080/v3/api-docs`. Health probe:
`http://localhost:8080/actuator/health`.

### POST `/v1/events/ingest`

Accepts a single event JSON object **or** a batch (array). Returns 201
with the persisted `List<SecurityEvent>`.

```bash
# Single event
curl -sS -X POST localhost:8080/v1/events/ingest \
    -H 'Content-Type: application/json' -d '{
      "eventId": "evt-00132",
      "timestamp": "2026-05-20T14:32:10Z",
      "configId": 14227,
      "clientIp": "203.0.113.42",
      "hostname": "www.example.com",
      "path": "/api/v1/login",
      "method": "POST",
      "statusCode": 403,
      "rule": {"id":"950001","name":"SQL_INJECTION",
               "severity":"CRITICAL","category":"INJECTION"},
      "action": "DENY"
    }'

# Batch
curl -sS -X POST localhost:8080/v1/events/ingest \
    -H 'Content-Type: application/json' -d '[ { ... }, { ... } ]'
```

Validation errors come back as 400 with `fieldErrors[]` and (for batch
requests) the offending event index.

### GET `/v1/stats/summary`

```bash
curl -s "localhost:8080/v1/stats/summary?configId=14227&from=2026-05-20T14:00:00Z&to=2026-05-20T15:00:00Z" | jq
```

Returns `totalEvents`, `byCategory` (counts + avg threat score keyed by
raw enum name), `byAction`, `topAttackers` (top 10 by count),
`topTargetedPaths` (top 10). Omit `configId` to aggregate across every
configuration.

### GET `/v1/events/samples`

```bash
curl -s "localhost:8080/v1/events/samples?limit=20&category=INJECTION" | jq
```

Filters: `configId`, `from`, `to`, `category`, `action`. Sorted by
`timestamp` desc, newest first. `limit` 1–100 (default 20), `offset`
≥ 0 (default 0). Response includes `total` for pagination.

### GET `/v1/stats/timeseries` *(bonus)*

```bash
curl -s "localhost:8080/v1/stats/timeseries?interval=5m&from=2026-05-20T14:00:00Z&to=2026-05-20T15:00:00Z" | jq
```

Returns event counts bucketed by `interval` for a line chart.
`interval` is required and must be one of `1m`, `5m`, `1h`.
`configId`, `from`, `to` are optional. `1m` and `1h` use Postgres
`date_trunc`; `5m` floors to a 5-minute mark via
`to_timestamp(FLOOR(EXTRACT(EPOCH FROM timestamp) / 300) * 300)`.
Empty buckets are skipped (not filled with zeros).

**Bonus choice.** The PDF offers three bonuses — alerting
(define/evaluate), time-series dashboard data, and rate limiting. I
picked time-series because it is a natural SQL extension of the Phase 7
stats endpoint, reuses the same `StatsFilter`, and demonstrates one of
the specific reasons for choosing Postgres over Elasticsearch in the
storage justification above. Rate limiting is called out in "What I'd
improve" because at Akamai scale it belongs at the edge, not the API.

## Data generator

Standalone Python 3 script at `scripts/generate.py` — tooling, not
product. Stdlib only (no `pip install`):

```bash
python3 scripts/generate.py \
    --count 10000 --waves 10 --wave-size 50 \
    --target http://localhost:8080/v1/events/ingest

# Or emit NDJSON (one JSON array per line) for later ingestion
python3 scripts/generate.py --count 10000 --output events.ndjson
```

See `python3 scripts/generate.py --help` for every flag.

## What I'd improve with more time

- **Kafka in front of ingest.** The real Akamai WSA buffers DLRs
  through a queue. Today `/v1/events/ingest` holds the client until
  the write + score + classify loop finishes. At real throughput
  (millions of events / sec) I would turn ingest into an async flow:
  the controller validates and publishes to Kafka, returns **202
  Accepted** immediately, and a consumer group enriches and persists.
  This also gives us natural backpressure, horizontal scaling of the
  enrichment workers, and replayability.
- **Redis cache for stats.** `GET /v1/stats/summary` runs five
  aggregations per request. For a SOC dashboard polling the same
  `(configId, from, to)` tuple every few seconds, a short-TTL
  (30s–5m, tuned to freshness tolerance) read-through cache keyed on
  the filter triple would collapse most of that load without touching
  the write path. Samples endpoint is harder to cache cleanly because
  of pagination, so I'd scope caching to stats first.
- **Rate limiting on the public API.** The PDF offers rate limiting as
  one of three bonuses; I argued in the "Bonus choice" subsection above
  that at Akamai scale it belongs at the edge (the real WSA sits behind
  Akamai itself), not in-application. If I were adding it in-app anyway
  I'd use Bucket4j with a per-client-IP token bucket on `/v1/stats` and
  `/v1/events/samples`, returning **429 Too Many Requests**. Mock the
  clock in tests to keep them deterministic.
- **Migrate the hot read path to Elasticsearch** for native
  `date_histogram` and ergonomic full-text search over user agents.
  Keep Postgres as the system of record.
- **Backpressure / rate control** between the generator and the ingest
  API — becomes less critical once Kafka is in place, but still needed
  for client-side protection against runaway producers.
- **Dead-letter queue** for ingest failures, so poisoned batches don't
  silently drop. Naturally falls out of the Kafka design above.
- **Expose Prometheus-formatted metrics** via `/actuator/prometheus`
  and wire them to Micrometer; add per-endpoint `@Operation` on the
  OpenAPI spec for richer Swagger descriptions.
- **Authentication** (none today).

## Challenges hit and how I solved them

- **Keeping the domain annotation-free while persisting to Postgres.**
  JPA would have forced `@Entity` + `@Table` + `@Column` onto
  `SecurityEvent`. Solution: `JdbcClient` with hand-written SQL in a
  dedicated `repository/jdbc/` adapter, and a `SecurityEventRepository`
  port interface the service layer depends on. The domain record has
  zero framework imports.
- **Per-element precision in batch validation errors.** Spring 6.1+
  raises `HandlerMethodValidationException` for `List<@Valid T>` and
  doesn't expose a clean per-element property path. Solution:
  `IngestionController` validates each batch element explicitly via an
  injected `jakarta.validation.Validator`, so a 400 response carries
  `fieldErrors[].index` and `fieldErrors[].field` matching the input
  shape.
- **Deterministic repeat-offender count within a single batch.**
  `IngestionService.ingestBatch` iterates sequentially (not with a
  parallel stream) so the Nth event's `countByClientIpSince` sees the
  prior N−1 events already persisted.
- **Idempotent re-ingestion.** The schema uses `UNIQUE (event_id)` and
  the INSERT uses `ON CONFLICT (event_id) DO NOTHING RETURNING id`.
  The adapter returns a `SecurityEvent` with `id = null` on duplicates,
  so re-POSTing the same batch is a visible no-op.

### Development notes

This project was developed with Claude Code as a pair-programmer. All
architectural decisions — storage choice (Postgres + `JdbcClient` over
JPA), annotation-free domain records, light hexagonal layout, the
Strategy pattern for threat scoring — were made by me after reviewing
trade-offs; Claude helped with boilerplate (SQL migrations, test
fixtures, docker-compose, Jackson configuration). The commit history
reflects the human decision sequence, not an AI dump. I can walk
through any part of the code in the interview and explain the
alternatives considered.

## One thing I learned

Postgres' `inet` column type combined with `JdbcClient`'s
`:paramName::inet` cast. The schema stores `client_ip` as `INET` so
Postgres can validate the IP at insert time and compare efficiently;
the Java side still passes a plain `String`. In the Jdbc adapter the
INSERT uses `VALUES (…, :clientIp::inet, …)` and the samples read
uses `HOST(client_ip)` to render it back as text. First time I needed
a per-value cast in a named-parameter query — I learned it by reading
the `pg_catalog` type pages and skimming the Spring 6.1 `JdbcClient`
Javadoc for the parameter-expansion rules.
