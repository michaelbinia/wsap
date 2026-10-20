---
name: run-demo
description: Start Mini WSA locally (Postgres + Spring Boot) and run a curl walkthrough of every endpoint with expected results, then tear down. Use when asked to run the app, demo it, smoke-test it end-to-end, or check that a change works against the real stack (not just tests).
---

# Run the Mini WSA demo locally

Starts Postgres 16 and the app, exercises each endpoint with curl, checks
the results against the expected values below, and tears everything down.

## 1. Prerequisites

- **JDK 21 with `javac`.** A JRE is not enough. Check
  `"$JAVA_HOME/bin/javac" -version`. If no JDK 21 exists, download Temurin
  into `/tmp/jdk-21` and set `JAVA_HOME=/tmp/jdk-21`. `/tmp` may be wiped
  between sessions, so re-check rather than assume.
- **Docker.** Ports 5432 and 8080 must be free:
  `ss -tlnp | grep -E ':5432|:8080'`.

## 2. Start Postgres

Prefer Compose if the plugin exists (`docker compose version`):

```bash
docker compose up -d postgres
```

Otherwise use plain `docker run` (same credentials as `application.yml`):

```bash
docker run -d --rm --name wsap-demo-pg \
  -e POSTGRES_DB=mini_wsa -e POSTGRES_USER=mini_wsa -e POSTGRES_PASSWORD=mini_wsa \
  -p 5432:5432 postgres:16
until docker exec wsap-demo-pg pg_isready -U mini_wsa -d mini_wsa >/dev/null 2>&1; do sleep 1; done
```

## 3. Start the app

Run from the repo root, in the background, logging to a file:

```bash
JAVA_HOME=<jdk21> nohup ./mvnw -B -ntp spring-boot:run > /tmp/wsap.log 2>&1 &
until curl -fsS localhost:8080/actuator/health >/dev/null 2>&1; do sleep 1; done
```

Ready in about 10 s. If it isn't up within 60 s, read `/tmp/wsap.log`.
Flyway migrates the schema on startup. Use a fresh database for each demo,
or the replay and burst numbers below will differ.

## 4. Walkthrough

Use the PDF's sample event as the base payload: `eventId` `evt-demo-001`,
`clientIp` `203.0.113.42`, path `/api/v1/login`, rule severity `CRITICAL`,
category `INJECTION`, action `DENY`. Use only RFC 5737 IPs (`203.0.113.x`,
`198.51.100.x`, `192.0.2.x`). Pipe JSON through `python3 -m json.tool` for
readability.

| # | Request | Expected |
|---|---|---|
| 1 | `GET /actuator/health` | `{"status":"UP"}` |
| 2 | `POST /v1/events/ingest` with a bare JSON object (not an array) | 201, one item `status: CREATED`, `threatScore: 75` (CRITICAL 40 + DENY 20 + `/login` 15), `attackType: "SQL/Command Injection"`, server-set `receivedAt` |
| 3 | POST 7 events in one array: same `clientIp`, path `/admin`, CRITICAL/DENY, distinct `eventId`s | Events 1–6 score 75; event 7 scores **90**. The +15 fires only with strictly more than 5 prior events |
| 4 | Re-POST step 2's event unchanged | **200**, `status: DUPLICATE`, original `id` and `threatScore` (stored values, not recomputed) |
| 5 | `GET /v1/stats/summary` | `totalEvents` 8, `byCategory`, `byAction`, `topAttackers`, `topTargetedPaths` populated |
| 6 | `GET /v1/events/samples?limit=3` | `total` 8, newest `timestamp` first |
| 7 | `GET /v1/events/samples?category=INJECTION&action=DENY` | Filtered results |
| 8 | `GET /v1/stats/timeseries?interval=1m` | Buckets in time order. Empty minutes are skipped, not zero-filled |
| 9 | POST with `rule.category: "BOGUS"` | 400 `Malformed request body` naming the enum |
| 10 | POST a 2-item array where item 1 omits `clientIp` | 400 `fieldErrors: [{index: 1, field: "clientIp", ...}]` |
| 11 | `GET /v1/stats/summary?from=2026-10-20T00:00:00Z&to=2026-10-18T00:00:00Z` | Currently 200 with an empty result (see README "Known limitations") |

Report each step as matching or not, and quote the actual response when
something differs.

The scores assume the default weights in `application.yml` under
`mini-wsa.scoring`. If those were changed, recompute what to expect
instead of reporting a failure.

## 5. Tear down — always

Run this even if a step failed:

```bash
pkill -f 'spring-boot:run'
docker stop wsap-demo-pg   # or: docker compose down
ss -tlnp | grep -E ':5432|:8080' || echo "ports free"
```

## Gotchas

- Don't `cd` into a directory and then delete it while running Java from
  it. The JVM fails with `platform encoding not initialized`.
- `mvnw.cmd` often shows as modified because of `.gitattributes`
  line-ending rules. Leave it out of commits.
- Known-limitation behaviours (the concurrency race, 409 on a malformed
  IP, non-atomic batches) are expected. Don't treat them as regressions.
