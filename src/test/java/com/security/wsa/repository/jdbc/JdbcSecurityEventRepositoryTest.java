package com.security.wsa.repository.jdbc;

import com.security.wsa.model.GeoLocation;
import com.security.wsa.model.Rule;
import com.security.wsa.model.SecurityEvent;
import com.security.wsa.model.enums.Action;
import com.security.wsa.model.enums.AttackCategory;
import com.security.wsa.model.enums.Severity;
import com.security.wsa.repository.SecurityEventRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.time.Duration;
import java.time.Instant;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest
@Testcontainers
class JdbcSecurityEventRepositoryTest {

    @Container
    static final PostgreSQLContainer<?> PG = new PostgreSQLContainer<>("postgres:16");

    @DynamicPropertySource
    static void props(DynamicPropertyRegistry r) {
        r.add("spring.datasource.url", PG::getJdbcUrl);
        r.add("spring.datasource.username", PG::getUsername);
        r.add("spring.datasource.password", PG::getPassword);
    }

    @Autowired
    SecurityEventRepository repo;

    @Autowired
    JdbcClient jdbc;

    @BeforeEach
    void clean() {
        jdbc.sql("DELETE FROM security_events").update();
    }

    @Test
    void countsOnlyMatchingIpAndStrictlyAfterThreshold() {
        Instant base = Instant.parse("2026-05-20T14:00:00Z");
        Instant threshold = base.minusSeconds(600);

        repo.save(event("1.1.1.1", base.minusSeconds(1200))); // before window
        repo.save(event("1.1.1.1", base.minusSeconds(300)));  // inside
        repo.save(event("1.1.1.1", base.minusSeconds(120)));  // inside
        repo.save(event("1.1.1.1", base));                     // inside
        repo.save(event("2.2.2.2", base.minusSeconds(60)));   // wrong IP

        assertThat(repo.countByClientIpInWindow("1.1.1.1", threshold, Instant.parse("2999-01-01T00:00:00Z"), "no-such-event"))
                .isEqualTo(3L);
    }

    @Test
    void repeatOffenderCountReadsReceivedAtNotTimestampSoBackdatedEventsCannotEscape() {
        Instant now = Instant.now();
        Instant backdated = now.minus(Duration.ofHours(1));

        for (int i = 0; i < 5; i++) {
            repo.save(eventWithReceivedAt(
                    "evt-prior-" + i, "1.1.1.1",
                    backdated,
                    now.minus(Duration.ofSeconds(60L * i))));
        }

        long count = repo.countByClientIpInWindow(
                "1.1.1.1",
                now.minus(Duration.ofMinutes(10)),
                now.plus(Duration.ofSeconds(1)),
                "evt-current");

        assertThat(count).isEqualTo(5L);
    }

    @Test
    void burstCountExcludesEventsReceivedAfterCurrentSoOutOfOrderIngestionIsStable() {
        Instant now = Instant.now();

        repo.save(eventWithReceivedAt("evt-earlier", "1.1.1.1",
                now.minus(Duration.ofMinutes(1)),
                now.minus(Duration.ofMinutes(1))));
        repo.save(eventWithReceivedAt("evt-later-but-earlier-timestamp", "1.1.1.1",
                now.minus(Duration.ofMinutes(2)),
                now.plus(Duration.ofSeconds(1))));

        long count = repo.countByClientIpInWindow(
                "1.1.1.1",
                now.minus(Duration.ofMinutes(10)),
                now,
                "evt-scored");

        assertThat(count).isEqualTo(1L);
    }

    @Test
    void burstCountExcludesTheCurrentEvent() {
        Instant now = Instant.now();
        repo.save(eventWithReceivedAt("evt-self", "1.1.1.1", now, now));

        long count = repo.countByClientIpInWindow(
                "1.1.1.1",
                now.minus(Duration.ofMinutes(10)),
                now.plus(Duration.ofSeconds(1)),
                "evt-self");

        assertThat(count).isZero();
    }

    @Test
    void saveReturnsIdOnFirstInsertAndNullOnDuplicateEventId() {
        SecurityEvent toSave = event("3.3.3.3", Instant.parse("2026-05-20T14:00:00Z"));

        SecurityEvent first = repo.save(toSave);
        assertThat(first.id()).isNotNull();

        SecurityEvent duplicate = repo.save(toSave);
        assertThat(duplicate.id()).isNull();
    }

    private static SecurityEvent event(String clientIp, Instant timestamp) {
        return eventWithReceivedAt("evt-" + UUID.randomUUID(), clientIp, timestamp, timestamp);
    }

    private static SecurityEvent eventWithReceivedAt(
            String eventId, String clientIp, Instant timestamp, Instant receivedAt) {
        return new SecurityEvent(
                null,
                eventId,
                timestamp,
                14227,
                "pol_web1",
                clientIp,
                "www.example.com",
                "/api/v1/login",
                "POST",
                403,
                "Mozilla/5.0",
                new Rule("950001", "SQL_INJECTION", "SQL Injection Attack Detected",
                        Severity.CRITICAL, AttackCategory.INJECTION),
                Action.DENY,
                new GeoLocation("CN", "Beijing"),
                1024L,
                256L,
                "SQL/Command Injection",
                85,
                receivedAt);
    }
}
