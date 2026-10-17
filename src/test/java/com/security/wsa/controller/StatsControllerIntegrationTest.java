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
import java.util.UUID;

import static org.hamcrest.Matchers.closeTo;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@Testcontainers
class StatsControllerIntegrationTest {

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
    void returnsEmptySummaryWhenNoEvents() throws Exception {
        mockMvc.perform(get("/v1/stats/summary"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.totalEvents").value(0))
                .andExpect(jsonPath("$.byCategory").isEmpty())
                .andExpect(jsonPath("$.byAction").isEmpty())
                .andExpect(jsonPath("$.topAttackers").isEmpty())
                .andExpect(jsonPath("$.topTargetedPaths").isEmpty());
    }

    @Test
    void aggregatesFilteredByConfigIdAndTimeRange() throws Exception {
        Instant base = Instant.parse("2026-05-20T14:00:00Z");

        // configId=14227, in range, INJECTION/DENY from 1.1.1.1 hitting /api/v1/login
        repository.save(event(14227, "1.1.1.1", "/api/v1/login", base.plusSeconds(10),
                Severity.CRITICAL, Action.DENY, AttackCategory.INJECTION, 80));
        repository.save(event(14227, "1.1.1.1", "/api/v1/login", base.plusSeconds(20),
                Severity.CRITICAL, Action.DENY, AttackCategory.INJECTION, 90));
        // configId=14227, in range, BOT/ALERT from 2.2.2.2 hitting /scrape
        repository.save(event(14227, "2.2.2.2", "/scrape", base.plusSeconds(30),
                Severity.LOW, Action.ALERT, AttackCategory.BOT, 40));
        // configId=99999, outside configId filter — should be excluded
        repository.save(event(99999, "9.9.9.9", "/other", base.plusSeconds(40),
                Severity.LOW, Action.MONITOR, AttackCategory.BOT, 10));
        // configId=14227 but before `from` — excluded
        repository.save(event(14227, "1.1.1.1", "/api/v1/login", base.minusSeconds(60),
                Severity.CRITICAL, Action.DENY, AttackCategory.INJECTION, 80));

        mockMvc.perform(get("/v1/stats/summary")
                        .param("configId", "14227")
                        .param("from", base.toString())
                        .param("to", base.plusSeconds(3600).toString()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.configId").value(14227))
                .andExpect(jsonPath("$.totalEvents").value(3))
                .andExpect(jsonPath("$.byCategory.INJECTION.count").value(2))
                .andExpect(jsonPath("$.byCategory.INJECTION.avgThreatScore").value(closeTo(85.0, 0.11)))
                .andExpect(jsonPath("$.byCategory.BOT.count").value(1))
                .andExpect(jsonPath("$.byCategory.BOT.avgThreatScore").value(closeTo(40.0, 0.11)))
                .andExpect(jsonPath("$.byAction.DENY").value(2))
                .andExpect(jsonPath("$.byAction.ALERT").value(1))
                .andExpect(jsonPath("$.topAttackers[0].clientIp").value("1.1.1.1"))
                .andExpect(jsonPath("$.topAttackers[0].count").value(2))
                .andExpect(jsonPath("$.topAttackers[0].avgThreatScore").value(closeTo(85.0, 0.11)))
                .andExpect(jsonPath("$.topAttackers[1].clientIp").value("2.2.2.2"))
                .andExpect(jsonPath("$.topTargetedPaths[0].path").value("/api/v1/login"))
                .andExpect(jsonPath("$.topTargetedPaths[0].count").value(2));
    }

    @Test
    void aggregatesAcrossAllConfigurationsWhenConfigIdOmitted() throws Exception {
        Instant base = Instant.parse("2026-05-20T14:00:00Z");

        repository.save(event(14227, "1.1.1.1", "/", base,
                Severity.LOW, Action.MONITOR, AttackCategory.BOT, 10));
        repository.save(event(99999, "2.2.2.2", "/", base.plusSeconds(1),
                Severity.LOW, Action.MONITOR, AttackCategory.BOT, 10));

        mockMvc.perform(get("/v1/stats/summary"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.configId").doesNotExist())
                .andExpect(jsonPath("$.totalEvents").value(2));
    }

    private static SecurityEvent event(int configId, String clientIp, String path,
                                       Instant timestamp,
                                       Severity severity, Action action,
                                       AttackCategory category, int score) {
        return new SecurityEvent(
                null,
                "evt-" + UUID.randomUUID(),
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
