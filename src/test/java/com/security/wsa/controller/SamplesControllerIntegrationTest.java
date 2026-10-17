package com.security.wsa.controller;

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
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.time.Instant;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@Testcontainers
class SamplesControllerIntegrationTest {

    @Container
    static final PostgreSQLContainer<?> PG = new PostgreSQLContainer<>("postgres:16");

    @DynamicPropertySource
    static void props(DynamicPropertyRegistry r) {
        r.add("spring.datasource.url", PG::getJdbcUrl);
        r.add("spring.datasource.username", PG::getUsername);
        r.add("spring.datasource.password", PG::getPassword);
    }

    @Autowired
    MockMvc mockMvc;

    @Autowired
    SecurityEventRepository repository;

    @Autowired
    JdbcClient jdbc;

    @BeforeEach
    void clean() {
        jdbc.sql("DELETE FROM security_events").update();
    }

    @Test
    void returnsEmptyPageWhenNoEventsMatch() throws Exception {
        mockMvc.perform(get("/v1/events/samples"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.total").value(0))
                .andExpect(jsonPath("$.events").isEmpty());
    }

    @Test
    void sortsByTimestampDescendingAndReturnsFullEventRecords() throws Exception {
        Instant base = Instant.parse("2026-05-20T14:00:00Z");

        repository.save(event("evt-oldest", 14227, "1.1.1.1", "/a", base,
                Severity.CRITICAL, Action.DENY, AttackCategory.INJECTION, 90));
        repository.save(event("evt-middle", 14227, "1.1.1.1", "/b", base.plusSeconds(10),
                Severity.HIGH, Action.ALERT, AttackCategory.XSS, 60));
        repository.save(event("evt-newest", 14227, "1.1.1.1", "/c", base.plusSeconds(20),
                Severity.LOW, Action.MONITOR, AttackCategory.BOT, 30));

        mockMvc.perform(get("/v1/events/samples"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.total").value(3))
                .andExpect(jsonPath("$.events[0].eventId").value("evt-newest"))
                .andExpect(jsonPath("$.events[0].rule.category").value("BOT"))
                .andExpect(jsonPath("$.events[0].clientIp").value("1.1.1.1"))
                .andExpect(jsonPath("$.events[0].attackType").value("SQL/Command Injection"))
                .andExpect(jsonPath("$.events[1].eventId").value("evt-middle"))
                .andExpect(jsonPath("$.events[2].eventId").value("evt-oldest"));
    }

    @Test
    void appliesCategoryAndActionFilters() throws Exception {
        Instant base = Instant.parse("2026-05-20T14:00:00Z");

        repository.save(event("inj-deny", 14227, "1.1.1.1", "/a", base.plusSeconds(1),
                Severity.CRITICAL, Action.DENY, AttackCategory.INJECTION, 90));
        repository.save(event("inj-alert", 14227, "1.1.1.1", "/b", base.plusSeconds(2),
                Severity.HIGH, Action.ALERT, AttackCategory.INJECTION, 60));
        repository.save(event("bot-deny", 14227, "1.1.1.1", "/c", base.plusSeconds(3),
                Severity.LOW, Action.DENY, AttackCategory.BOT, 30));

        mockMvc.perform(get("/v1/events/samples")
                        .param("category", "INJECTION")
                        .param("action", "DENY"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.total").value(1))
                .andExpect(jsonPath("$.events[0].eventId").value("inj-deny"));
    }

    @Test
    void appliesLimitAndOffsetAndReportsFullTotal() throws Exception {
        Instant base = Instant.parse("2026-05-20T14:00:00Z");
        for (int i = 0; i < 5; i++) {
            repository.save(event("evt-" + i, 14227, "1.1.1.1", "/p", base.plusSeconds(i),
                    Severity.LOW, Action.MONITOR, AttackCategory.BOT, 10));
        }

        mockMvc.perform(get("/v1/events/samples")
                        .param("limit", "2")
                        .param("offset", "1"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.total").value(5))
                .andExpect(jsonPath("$.events.length()").value(2))
                .andExpect(jsonPath("$.events[0].eventId").value("evt-3"))
                .andExpect(jsonPath("$.events[1].eventId").value("evt-2"));
    }

    @Test
    void returns400WhenLimitExceedsMax() throws Exception {
        mockMvc.perform(get("/v1/events/samples").param("limit", "101"))
                .andExpect(status().isBadRequest());
    }

    @Test
    void returns400WhenOffsetIsNegative() throws Exception {
        mockMvc.perform(get("/v1/events/samples").param("offset", "-1"))
                .andExpect(status().isBadRequest());
    }

    @Test
    void returns400WhenCategoryEnumValueIsInvalid() throws Exception {
        mockMvc.perform(get("/v1/events/samples").param("category", "BOGUS"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("Invalid request parameter"));
    }

    private static SecurityEvent event(String eventId, int configId, String clientIp, String path,
                                       Instant timestamp,
                                       Severity severity, Action action,
                                       AttackCategory category, int score) {
        return new SecurityEvent(
                null,
                eventId,
                timestamp,
                configId,
                "pol_web1",
                clientIp,
                "www.example.com",
                path,
                "POST",
                200,
                "Mozilla/5.0",
                new Rule("950001", "SQL_INJECTION", null, severity, category),
                action,
                new GeoLocation("CN", "Beijing"),
                null, null,
                "SQL/Command Injection",
                score,
                timestamp);
    }
}
