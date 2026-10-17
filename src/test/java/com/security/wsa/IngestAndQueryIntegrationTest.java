package com.security.wsa;

import com.security.wsa.controller.ErrorResponse;
import com.security.wsa.controller.FieldErrorDetail;
import com.security.wsa.model.GeoLocationDto;
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

        ResponseEntity<List<SecurityEvent>> ingestResponse = rest.exchange(
                "/v1/events/ingest",
                HttpMethod.POST,
                new HttpEntity<>(batch),
                new ParameterizedTypeReference<List<SecurityEvent>>() {
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
