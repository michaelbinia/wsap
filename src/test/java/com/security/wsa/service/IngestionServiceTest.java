package com.security.wsa.service;

import com.security.wsa.model.GeoLocationDto;
import com.security.wsa.model.RuleDto;
import com.security.wsa.model.SecurityEvent;
import com.security.wsa.model.SecurityEventDto;
import com.security.wsa.model.enums.Action;
import com.security.wsa.model.enums.AttackCategory;
import com.security.wsa.model.enums.Severity;
import com.security.wsa.repository.SecurityEventRepository;
import com.security.wsa.service.enrichment.AttackClassifier;
import com.security.wsa.service.enrichment.ThreatScoreCalculator;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.InOrder;

import java.time.Duration;
import java.time.Instant;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class IngestionServiceTest {

    private SecurityEventRepository repository;
    private ThreatScoreCalculator threatScoreCalculator;
    private AttackClassifier attackClassifier;
    private IngestionService service;

    @BeforeEach
    void setUp() {
        repository = mock(SecurityEventRepository.class);
        threatScoreCalculator = mock(ThreatScoreCalculator.class);
        attackClassifier = mock(AttackClassifier.class);
        service = new IngestionService(repository, threatScoreCalculator, attackClassifier);

        when(repository.save(any())).thenAnswer(invocation -> invocation.getArgument(0));
    }

    @Test
    void ingestOneEnrichesAndPersists() {
        SecurityEventDto dto = dto("evt-1", "203.0.113.42",
                Instant.parse("2026-05-20T14:32:10Z"),
                Severity.CRITICAL, Action.DENY, AttackCategory.INJECTION, "/api/v1/login");

        when(repository.countByClientIpSince(eq("203.0.113.42"), any(Instant.class))).thenReturn(7L);
        when(threatScoreCalculator.calculateScore(dto, 7L)).thenReturn(85);
        when(attackClassifier.classify(AttackCategory.INJECTION)).thenReturn("SQL/Command Injection");

        SecurityEvent saved = service.ingestOne(dto);

        ArgumentCaptor<Instant> thresholdCaptor = ArgumentCaptor.forClass(Instant.class);
        verify(repository).countByClientIpSince(eq("203.0.113.42"), thresholdCaptor.capture());
        assertThat(thresholdCaptor.getValue())
                .isEqualTo(dto.timestamp().minus(Duration.ofMinutes(10)));

        ArgumentCaptor<SecurityEvent> savedCaptor = ArgumentCaptor.forClass(SecurityEvent.class);
        verify(repository).save(savedCaptor.capture());
        SecurityEvent persisted = savedCaptor.getValue();

        assertThat(persisted.id()).isNull();
        assertThat(persisted.eventId()).isEqualTo("evt-1");
        assertThat(persisted.threatScore()).isEqualTo(85);
        assertThat(persisted.attackType()).isEqualTo("SQL/Command Injection");
        assertThat(persisted.rule().category()).isEqualTo(AttackCategory.INJECTION);
        assertThat(persisted.action()).isEqualTo(Action.DENY);
        assertThat(persisted.receivedAt()).isNotNull();

        assertThat(saved).isSameAs(persisted);
    }

    @Test
    void ingestOneAttackTypeDerivesFromRuleCategoryNotScore() {
        SecurityEventDto dto = dto("evt-2", "1.2.3.4",
                Instant.parse("2026-05-20T14:32:10Z"),
                Severity.LOW, Action.MONITOR, AttackCategory.BOT, "/");

        when(repository.countByClientIpSince(any(), any())).thenReturn(0L);
        when(threatScoreCalculator.calculateScore(any(), anyLong())).thenReturn(99);
        when(attackClassifier.classify(AttackCategory.BOT)).thenReturn("Bot Activity");

        SecurityEvent saved = service.ingestOne(dto);

        assertThat(saved.attackType()).isEqualTo("Bot Activity");
        assertThat(saved.threatScore()).isEqualTo(99);
    }

    @Test
    void ingestOneHandlesMissingGeoLocation() {
        RuleDto rule = new RuleDto("950001", "SQL_INJECTION",
                "SQL Injection Attack Detected", Severity.LOW, AttackCategory.BOT);
        SecurityEventDto dto = new SecurityEventDto(
                "evt-3", Instant.parse("2026-05-20T14:32:10Z"), 14227, "pol_web1",
                "5.6.7.8", "www.example.com", "/", "POST", 403,
                "Mozilla/5.0", rule, Action.MONITOR,
                null,
                1024L, 256L);
        when(attackClassifier.classify(any())).thenReturn("Bot Activity");

        SecurityEvent saved = service.ingestOne(dto);

        assertThat(saved.geoLocation()).isNull();
    }

    @Test
    void ingestBatchProcessesEventsInOrderSoRepeatOffenderCountSeesPriorEvents() {
        SecurityEventDto first = dto("evt-a", "1.1.1.1",
                Instant.parse("2026-05-20T14:32:10Z"),
                Severity.LOW, Action.MONITOR, AttackCategory.BOT, "/");
        SecurityEventDto second = dto("evt-b", "1.1.1.1",
                Instant.parse("2026-05-20T14:32:11Z"),
                Severity.LOW, Action.MONITOR, AttackCategory.BOT, "/");
        when(attackClassifier.classify(any())).thenReturn("Bot Activity");

        service.ingestBatch(List.of(first, second));

        InOrder inOrder = inOrder(repository);
        inOrder.verify(repository).countByClientIpSince(eq("1.1.1.1"),
                eq(first.timestamp().minus(Duration.ofMinutes(10))));
        inOrder.verify(repository).save(any());
        inOrder.verify(repository).countByClientIpSince(eq("1.1.1.1"),
                eq(second.timestamp().minus(Duration.ofMinutes(10))));
        inOrder.verify(repository).save(any());
    }

    private static SecurityEventDto dto(String eventId, String clientIp, Instant timestamp,
                                        Severity severity, Action action,
                                        AttackCategory category, String path) {
        RuleDto rule = new RuleDto("950001", "SQL_INJECTION",
                "SQL Injection Attack Detected", severity, category);
        return new SecurityEventDto(
                eventId, timestamp, 14227, "pol_web1",
                clientIp, "www.example.com", path, "POST", 403,
                "Mozilla/5.0", rule, action,
                new GeoLocationDto("CN", "Beijing"),
                1024L, 256L);
    }
}
