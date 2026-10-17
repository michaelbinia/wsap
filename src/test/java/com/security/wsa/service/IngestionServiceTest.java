package com.security.wsa.service;

import com.security.wsa.model.GeoLocationDto;
import com.security.wsa.model.RuleDto;
import com.security.wsa.model.SecurityEvent;
import com.security.wsa.model.SecurityEventDto;
import com.security.wsa.model.enums.Action;
import com.security.wsa.model.enums.AttackCategory;
import com.security.wsa.model.enums.Severity;
import com.security.wsa.config.MiniWsaProperties;
import com.security.wsa.config.TestProperties;
import com.security.wsa.repository.SecurityEventRepository;
import com.security.wsa.service.enrichment.AttackClassifier;
import com.security.wsa.service.enrichment.ThreatScoreCalculator;
import com.security.wsa.service.enrichment.rules.ActionEvaluationRule;
import com.security.wsa.service.enrichment.rules.RepeatOffenderEvaluationRule;
import com.security.wsa.service.enrichment.rules.SensitivePathEvaluationRule;
import com.security.wsa.service.enrichment.rules.SeverityEvaluationRule;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.InOrder;

import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.within;
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
        service = new IngestionService(repository, threatScoreCalculator, attackClassifier,
                TestProperties.pdfDefaults());

        when(repository.save(any())).thenAnswer(invocation -> invocation.getArgument(0));
    }

    @Test
    void ingestOneEnrichesAndPersists() {
        SecurityEventDto dto = dto("evt-1", "203.0.113.42",
                Instant.parse("2026-05-20T14:32:10Z"),
                Severity.CRITICAL, Action.DENY, AttackCategory.INJECTION, "/api/v1/login");

        when(repository.countByClientIpInWindow(eq("203.0.113.42"), any(Instant.class), any(Instant.class), eq("evt-1")))
                .thenReturn(7L);
        when(threatScoreCalculator.calculateScore(dto, 7L)).thenReturn(85);
        when(attackClassifier.classify(AttackCategory.INJECTION)).thenReturn("SQL/Command Injection");

        SecurityEvent saved = service.ingestOne(dto);

        ArgumentCaptor<Instant> fromCaptor = ArgumentCaptor.forClass(Instant.class);
        ArgumentCaptor<Instant> toCaptor = ArgumentCaptor.forClass(Instant.class);
        verify(repository).countByClientIpInWindow(
                eq("203.0.113.42"), fromCaptor.capture(), toCaptor.capture(), eq("evt-1"));
        Instant nowRef = Instant.now();
        assertThat(toCaptor.getValue()).isCloseTo(nowRef, within(5, ChronoUnit.SECONDS));
        assertThat(fromCaptor.getValue())
                .isEqualTo(toCaptor.getValue().minus(Duration.ofMinutes(10)));

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

        when(repository.countByClientIpInWindow(any(), any(), any(), any())).thenReturn(0L);
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
    void ingestOneRunsTheRealScoringStackAndComputesPdfScore() {
        SecurityEventRepository realStackRepo = mock(SecurityEventRepository.class);
        when(realStackRepo.save(any())).thenAnswer(invocation -> invocation.getArgument(0));
        when(realStackRepo.countByClientIpInWindow(any(), any(), any(), any())).thenReturn(0L);
        MiniWsaProperties props = TestProperties.pdfDefaults();
        ThreatScoreCalculator realCalculator = new ThreatScoreCalculator(List.of(
                new SeverityEvaluationRule(props),
                new ActionEvaluationRule(props),
                new SensitivePathEvaluationRule(props),
                new RepeatOffenderEvaluationRule(props)), props);
        AttackClassifier realClassifier = new AttackClassifier();
        IngestionService realStackService = new IngestionService(realStackRepo, realCalculator, realClassifier, props);

        SecurityEventDto input = dto("evt-real", "203.0.113.42",
                Instant.parse("2026-05-20T14:32:10Z"),
                Severity.CRITICAL, Action.DENY, AttackCategory.INJECTION, "/admin");

        SecurityEvent saved = realStackService.ingestOne(input);

        // CRITICAL(40) + DENY(20) + /admin path(15) + no repeat(0) = 75
        assertThat(saved.threatScore()).isEqualTo(75);
        assertThat(saved.attackType()).isEqualTo("SQL/Command Injection");
        assertThat(saved.receivedAt()).isNotNull();
        assertThat(saved.id()).isNull();
        // Original DLR fields preserved
        assertThat(saved.eventId()).isEqualTo("evt-real");
        assertThat(saved.clientIp()).isEqualTo("203.0.113.42");
        assertThat(saved.timestamp()).isEqualTo(Instant.parse("2026-05-20T14:32:10Z"));
        assertThat(saved.rule().category()).isEqualTo(AttackCategory.INJECTION);
        assertThat(saved.action()).isEqualTo(Action.DENY);
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
        inOrder.verify(repository).countByClientIpInWindow(
                eq("1.1.1.1"), any(Instant.class), any(Instant.class), eq("evt-a"));
        inOrder.verify(repository).save(any());
        inOrder.verify(repository).countByClientIpInWindow(
                eq("1.1.1.1"), any(Instant.class), any(Instant.class), eq("evt-b"));
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
