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
class TimeSeriesControllerIntegrationTest {

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
    void returnsEmptyBucketsWhenNoEvents() throws Exception {
        mockMvc.perform(get("/v1/stats/timeseries").param("interval", "1m"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.interval").value("1m"))
                .andExpect(jsonPath("$.buckets").isEmpty());
    }

    @Test
    void onePerMinuteBucketPerDistinctMinute() throws Exception {
        // 3 events at 14:00:xx, 2 events at 14:01:xx, 1 event at 14:03:xx
        Instant t1400 = Instant.parse("2026-05-20T14:00:00Z");
        Instant t1401 = Instant.parse("2026-05-20T14:01:00Z");
        Instant t1403 = Instant.parse("2026-05-20T14:03:00Z");

        repository.save(event("evt-ts-a", t1400.plusSeconds(5)));
        repository.save(event("evt-ts-b", t1400.plusSeconds(20)));
        repository.save(event("evt-ts-c", t1400.plusSeconds(55)));
        repository.save(event("evt-ts-d", t1401.plusSeconds(10)));
        repository.save(event("evt-ts-e", t1401.plusSeconds(40)));
        repository.save(event("evt-ts-f", t1403.plusSeconds(0)));

        mockMvc.perform(get("/v1/stats/timeseries").param("interval", "1m"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.interval").value("1m"))
                .andExpect(jsonPath("$.buckets.length()").value(3))
                .andExpect(jsonPath("$.buckets[0].start").value("2026-05-20T14:00:00Z"))
                .andExpect(jsonPath("$.buckets[0].count").value(3))
                .andExpect(jsonPath("$.buckets[1].start").value("2026-05-20T14:01:00Z"))
                .andExpect(jsonPath("$.buckets[1].count").value(2))
                .andExpect(jsonPath("$.buckets[2].start").value("2026-05-20T14:03:00Z"))
                .andExpect(jsonPath("$.buckets[2].count").value(1));
    }

    @Test
    void fiveMinuteBucketsFloorToMultipleOfFive() throws Exception {
        // 2 events in the 14:00-14:04 bucket, 1 event in the 14:05-14:09 bucket
        repository.save(event("evt-5m-a", Instant.parse("2026-05-20T14:00:30Z")));
        repository.save(event("evt-5m-b", Instant.parse("2026-05-20T14:04:30Z")));
        repository.save(event("evt-5m-c", Instant.parse("2026-05-20T14:07:15Z")));

        mockMvc.perform(get("/v1/stats/timeseries").param("interval", "5m"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.buckets.length()").value(2))
                .andExpect(jsonPath("$.buckets[0].start").value("2026-05-20T14:00:00Z"))
                .andExpect(jsonPath("$.buckets[0].count").value(2))
                .andExpect(jsonPath("$.buckets[1].start").value("2026-05-20T14:05:00Z"))
                .andExpect(jsonPath("$.buckets[1].count").value(1));
    }

    @Test
    void oneHourBucketsAggregateIntoHourStarts() throws Exception {
        repository.save(event("evt-1h-a", Instant.parse("2026-05-20T14:00:30Z")));
        repository.save(event("evt-1h-b", Instant.parse("2026-05-20T14:30:00Z")));
        repository.save(event("evt-1h-c", Instant.parse("2026-05-20T14:59:59Z")));
        repository.save(event("evt-1h-d", Instant.parse("2026-05-20T15:05:00Z")));

        mockMvc.perform(get("/v1/stats/timeseries").param("interval", "1h"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.buckets.length()").value(2))
                .andExpect(jsonPath("$.buckets[0].start").value("2026-05-20T14:00:00Z"))
                .andExpect(jsonPath("$.buckets[0].count").value(3))
                .andExpect(jsonPath("$.buckets[1].start").value("2026-05-20T15:00:00Z"))
                .andExpect(jsonPath("$.buckets[1].count").value(1));
    }

    @Test
    void returns400OnUnknownInterval() throws Exception {
        mockMvc.perform(get("/v1/stats/timeseries").param("interval", "10m"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.message").value("interval must be one of: 1m, 5m, 1h"));
    }

    @Test
    void returns400WhenIntervalIsMissing() throws Exception {
        mockMvc.perform(get("/v1/stats/timeseries"))
                .andExpect(status().isBadRequest());
    }

    private static SecurityEvent event(String eventId, Instant timestamp) {
        return new SecurityEvent(
                null,
                eventId,
                timestamp,
                14227,
                "pol_web1",
                "203.0.113.42",
                "www.example.com",
                "/",
                "GET",
                200,
                "Mozilla/5.0",
                new Rule("950001", "SQL_INJECTION", null, Severity.LOW, AttackCategory.BOT),
                Action.MONITOR,
                new GeoLocation("CN", "Beijing"),
                null, null,
                "Bot Activity",
                10,
                timestamp);
    }
}
