package com.security.wsa;

import com.security.wsa.controller.ErrorResponse;
import com.security.wsa.controller.FieldErrorDetail;
import com.security.wsa.model.GeoLocationDto;
import com.security.wsa.model.IngestResult;
import com.security.wsa.model.RuleDto;
import com.security.wsa.model.SamplesResponse;
import com.security.wsa.model.SecurityEvent;
import com.security.wsa.model.SecurityEventDto;
import com.security.wsa.model.StatsSummaryResponse;
import com.security.wsa.model.enums.Action;
import com.security.wsa.model.enums.AttackCategory;
import com.security.wsa.model.enums.Severity;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@Testcontainers
class IngestAndQueryIntegrationTest {

    @Container
    static final PostgreSQLContainer<?> PG = new PostgreSQLContainer<>("postgres:16");

    @DynamicPropertySource
    static void props(DynamicPropertyRegistry r) {
        r.add("spring.datasource.url", PG::getJdbcUrl);
        r.add("spring.datasource.username", PG::getUsername);
        r.add("spring.datasource.password", PG::getPassword);
    }

    @Autowired
    TestRestTemplate rest;

    @Autowired
    JdbcClient jdbc;

    @BeforeEach
    void clean() {
        jdbc.sql("DELETE FROM security_events").update();
    }

    @Test
    void ingestsBatchThenSamplesAndStatsReflectTheIngestedData() {
        Instant base = Instant.parse("2026-05-20T14:00:00Z");
        List<SecurityEventDto> batch = new ArrayList<>(20);
        for (int i = 0; i < 10; i++) {
            batch.add(injectionDeny("evt-inj-" + i, base.plusSeconds(i), "203.0.113." + (10 + i)));
        }
        for (int i = 0; i < 10; i++) {
            batch.add(botMonitor("evt-bot-" + i, base.plusSeconds(100 + i), "198.51.100." + (10 + i)));
        }

        ResponseEntity<List<IngestResult>> ingestResponse = rest.exchange(
                "/v1/events/ingest",
                HttpMethod.POST,
                new HttpEntity<>(batch),
                new ParameterizedTypeReference<List<IngestResult>>() {
                });
        assertThat(ingestResponse.getStatusCode()).isEqualTo(HttpStatus.CREATED);
        assertThat(ingestResponse.getBody()).hasSize(20);

        ResponseEntity<SamplesResponse> samplesResponse = rest.getForEntity(
                "/v1/events/samples?limit=20", SamplesResponse.class);
        assertThat(samplesResponse.getStatusCode()).isEqualTo(HttpStatus.OK);
        SamplesResponse samples = samplesResponse.getBody();
        assertThat(samples).isNotNull();
        assertThat(samples.total()).isGreaterThanOrEqualTo(20L);
        assertThat(samples.events())
                .hasSize(20)
                .isSortedAccordingTo(Comparator.comparing(SecurityEvent::timestamp).reversed());

        ResponseEntity<StatsSummaryResponse> statsResponse = rest.getForEntity(
                "/v1/stats/summary", StatsSummaryResponse.class);
        assertThat(statsResponse.getStatusCode()).isEqualTo(HttpStatus.OK);
        StatsSummaryResponse stats = statsResponse.getBody();
        assertThat(stats).isNotNull();
        assertThat(stats.totalEvents()).isGreaterThanOrEqualTo(20L);
        assertThat(stats.byCategory()).containsKeys("INJECTION", "BOT");
        assertThat(stats.byAction()).containsKeys("DENY", "MONITOR");
        assertThat(stats.byAction().get("DENY")).isEqualTo(10L);
        assertThat(stats.byAction().get("MONITOR")).isEqualTo(10L);
    }

    @Test
    void returns400WithFieldErrorsWhenClientIpIsMissing() {
        String missingClientIp = """
                [{
                  "eventId": "evt-missing",
                  "timestamp": "2026-05-20T14:00:00Z",
                  "configId": 14227,
                  "hostname": "www.example.com",
                  "path": "/",
                  "method": "GET",
                  "statusCode": 200,
                  "rule": {
                    "id": "r", "name": "n",
                    "severity": "LOW", "category": "BOT"
                  },
                  "action": "MONITOR"
                }]
                """;

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);

        ResponseEntity<ErrorResponse> response = rest.exchange(
                "/v1/events/ingest",
                HttpMethod.POST,
                new HttpEntity<>(missingClientIp, headers),
                ErrorResponse.class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(response.getBody()).isNotNull();
        assertThat(response.getBody().fieldErrors())
                .extracting(FieldErrorDetail::field)
                .contains("clientIp");
        assertThat(response.getBody().fieldErrors())
                .extracting(FieldErrorDetail::index)
                .contains(0);
    }

    @Test
    void scoreAttackTypeAndReceivedAtRoundTripThroughPostgres() {
        SecurityEventDto event = new SecurityEventDto(
                "evt-round-trip",
                Instant.parse("2026-05-20T14:00:00Z"),
                14227, "pol_web1",
                "203.0.113.42", "www.example.com", "/admin", "POST", 403,
                "Mozilla/5.0",
                new RuleDto("950001", "SQL_INJECTION", "SQL Injection Attack Detected",
                        Severity.CRITICAL, AttackCategory.INJECTION),
                Action.DENY,
                new GeoLocationDto("CN", "Beijing"),
                1024L, 256L);

        ResponseEntity<List<IngestResult>> ingest = rest.exchange(
                "/v1/events/ingest",
                HttpMethod.POST,
                new HttpEntity<>(List.of(event)),
                new ParameterizedTypeReference<List<IngestResult>>() {
                });
        assertThat(ingest.getStatusCode()).isEqualTo(HttpStatus.CREATED);

        ResponseEntity<SamplesResponse> samples = rest.getForEntity(
                "/v1/events/samples?limit=1", SamplesResponse.class);
        assertThat(samples.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(samples.getBody()).isNotNull();
        assertThat(samples.getBody().events()).hasSize(1);

        SecurityEvent persisted = samples.getBody().events().get(0);
        // CRITICAL(40) + DENY(20) + /admin path(15) + no repeat(0) = 75
        assertThat(persisted.threatScore()).isEqualTo(75);
        assertThat(persisted.attackType()).isEqualTo("SQL/Command Injection");
        assertThat(persisted.receivedAt()).isNotNull();
        assertThat(persisted.eventId()).isEqualTo("evt-round-trip");
        assertThat(persisted.rule().category()).isEqualTo(AttackCategory.INJECTION);
    }

    @Test
    void reIngestingTheSameBatchIsIdempotentOnEventId() {
        Instant base = Instant.parse("2026-05-20T14:00:00Z");
        List<SecurityEventDto> batch = new ArrayList<>();
        for (int i = 0; i < 20; i++) {
            batch.add(injectionDeny("evt-dup-" + i, base.plusSeconds(i), "203.0.113." + (10 + i)));
        }

        ResponseEntity<List<IngestResult>> firstPost = rest.exchange(
                "/v1/events/ingest", HttpMethod.POST, new HttpEntity<>(batch),
                new ParameterizedTypeReference<List<IngestResult>>() {
                });
        assertThat(firstPost.getStatusCode()).isEqualTo(HttpStatus.CREATED);
        assertThat(firstPost.getBody()).allSatisfy(r -> {
            assertThat(r.status()).isEqualTo(IngestResult.Status.CREATED);
            assertThat(r.event().id()).isNotNull();
        });

        ResponseEntity<List<IngestResult>> secondPost = rest.exchange(
                "/v1/events/ingest", HttpMethod.POST, new HttpEntity<>(batch),
                new ParameterizedTypeReference<List<IngestResult>>() {
                });
        assertThat(secondPost.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(secondPost.getBody()).allSatisfy(r -> {
            assertThat(r.status()).isEqualTo(IngestResult.Status.DUPLICATE);
            assertThat(r.event().id()).isNotNull();
        });

        ResponseEntity<StatsSummaryResponse> stats = rest.getForEntity(
                "/v1/stats/summary", StatsSummaryResponse.class);
        assertThat(stats.getBody()).isNotNull();
        assertThat(stats.getBody().totalEvents()).isEqualTo(20L);
    }

    @Test
    void repeatOffenderBonusFiresAfterMoreThanFiveEventsFromSameIp() {
        Instant base = Instant.parse("2026-05-20T14:00:00Z");
        List<SecurityEventDto> seven = new ArrayList<>();
        for (int i = 0; i < 7; i++) {
            seven.add(new SecurityEventDto(
                    "evt-repeat-" + i,
                    base.plusSeconds(i),
                    14227, "pol_web1",
                    "203.0.113.99", "www.example.com", "/", "GET", 200,
                    "Mozilla/5.0",
                    new RuleDto("913001", "BOT_ACTIVITY", "Automated Bot Request",
                            Severity.LOW, AttackCategory.BOT),
                    Action.MONITOR,
                    new GeoLocationDto("US", "San Francisco"),
                    100L, 100L));
        }

        ResponseEntity<List<IngestResult>> ingest = rest.exchange(
                "/v1/events/ingest", HttpMethod.POST, new HttpEntity<>(seven),
                new ParameterizedTypeReference<List<IngestResult>>() {
                });
        assertThat(ingest.getStatusCode()).isEqualTo(HttpStatus.CREATED);

        ResponseEntity<SamplesResponse> samples = rest.getForEntity(
                "/v1/events/samples?limit=10", SamplesResponse.class);
        assertThat(samples.getBody()).isNotNull();
        List<SecurityEvent> events = samples.getBody().events();
        assertThat(events).hasSize(7);

        // Newest-first ordering: events[0] is the 7th ingested — sees 6 prior same-IP events.
        // LOW(10) + MONITOR(0) + path "/"(0) + repeat(15) = 25.
        assertThat(events.get(0).eventId()).isEqualTo("evt-repeat-6");
        assertThat(events.get(0).threatScore()).isEqualTo(25);
        // Every earlier event sees <= 5 priors from this IP: no bonus. LOW only.
        for (int i = 1; i < events.size(); i++) {
            assertThat(events.get(i).threatScore())
                    .as("event %s should have the base LOW/MONITOR score only", events.get(i).eventId())
                    .isEqualTo(10);
        }
    }

    @Test
    void singleEventBodyIsAcceptedAlongsideBatch() {
        SecurityEventDto single = injectionDeny(
                "evt-single",
                Instant.parse("2026-05-20T14:00:00Z"),
                "203.0.113.1");

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);

        ResponseEntity<List<IngestResult>> ingest = rest.exchange(
                "/v1/events/ingest",
                HttpMethod.POST,
                new HttpEntity<>(single, headers),
                new ParameterizedTypeReference<List<IngestResult>>() {
                });
        assertThat(ingest.getStatusCode()).isEqualTo(HttpStatus.CREATED);
        assertThat(ingest.getBody()).hasSize(1);
        assertThat(ingest.getBody().get(0).status()).isEqualTo(IngestResult.Status.CREATED);
        assertThat(ingest.getBody().get(0).event().eventId()).isEqualTo("evt-single");

        ResponseEntity<SamplesResponse> samples = rest.getForEntity(
                "/v1/events/samples?limit=5", SamplesResponse.class);
        assertThat(samples.getBody()).isNotNull();
        assertThat(samples.getBody().total()).isEqualTo(1L);
        assertThat(samples.getBody().events()).extracting(SecurityEvent::eventId)
                .containsExactly("evt-single");
    }

    private static SecurityEventDto injectionDeny(String eventId, Instant timestamp, String clientIp) {
        return new SecurityEventDto(
                eventId, timestamp, 14227, "pol_web1",
                clientIp, "www.example.com", "/api/v1/login", "POST", 403,
                "Mozilla/5.0",
                new RuleDto("950001", "SQL_INJECTION", "SQL Injection Attack Detected",
                        Severity.CRITICAL, AttackCategory.INJECTION),
                Action.DENY,
                new GeoLocationDto("CN", "Beijing"),
                1024L, 256L);
    }

    private static SecurityEventDto botMonitor(String eventId, Instant timestamp, String clientIp) {
        return new SecurityEventDto(
                eventId, timestamp, 14227, "pol_web1",
                clientIp, "www.example.com", "/scrape", "GET", 200,
                "GoogleBot/2.1",
                new RuleDto("913001", "BOT_ACTIVITY", "Automated Bot Request",
                        Severity.LOW, AttackCategory.BOT),
                Action.MONITOR,
                new GeoLocationDto("US", "San Francisco"),
                512L, 1024L);
    }
}
