package com.security.wsa.service.enrichment;

import com.security.wsa.config.MiniWsaProperties;
import com.security.wsa.config.TestProperties;
import com.security.wsa.model.SecurityEventDto;
import com.security.wsa.model.enums.Action;
import com.security.wsa.model.enums.Severity;
import com.security.wsa.service.enrichment.rules.ActionEvaluationRule;
import com.security.wsa.service.enrichment.rules.RepeatOffenderEvaluationRule;
import com.security.wsa.service.enrichment.rules.SensitivePathEvaluationRule;
import com.security.wsa.service.enrichment.rules.SeverityEvaluationRule;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class ThreatScoreCalculatorTest {

    @Test
    void sumsEveryRuleContribution() {
        MiniWsaProperties props = TestProperties.pdfDefaults();
        ThreatScoreCalculator calc = new ThreatScoreCalculator(List.of(
                (event, count) -> 10,
                (event, count) -> 25,
                (event, count) -> 5), props);

        int score = calc.calculateScore(TestFixtures.event(Severity.LOW, Action.MONITOR, "/"), 0L);

        assertThat(score).isEqualTo(40);
    }

    @Test
    void capsScoreAt100() {
        MiniWsaProperties props = TestProperties.pdfDefaults();
        ThreatScoreCalculator calc = new ThreatScoreCalculator(List.of(
                (event, count) -> 60,
                (event, count) -> 50,
                (event, count) -> 30), props);

        int score = calc.calculateScore(TestFixtures.event(Severity.LOW, Action.MONITOR, "/"), 0L);

        assertThat(score).isEqualTo(100);
    }

    @Test
    void returnsZeroWhenNoRulesAreRegistered() {
        MiniWsaProperties props = TestProperties.pdfDefaults();
        ThreatScoreCalculator calc = new ThreatScoreCalculator(List.of(), props);

        int score = calc.calculateScore(TestFixtures.event(Severity.CRITICAL, Action.DENY, "/admin/login"), 100L);

        assertThat(score).isZero();
    }

    @Test
    void composesTheFourProductionRulesForTheWorstCaseEvent() {
        MiniWsaProperties props = TestProperties.pdfDefaults();
        ThreatScoreCalculator calc = new ThreatScoreCalculator(List.of(
                new SeverityEvaluationRule(props),
                new ActionEvaluationRule(props),
                new SensitivePathEvaluationRule(props),
                new RepeatOffenderEvaluationRule(props)),
                props);

        SecurityEventDto event = TestFixtures.event(Severity.CRITICAL, Action.DENY, "/api/v1/admin/login");

        // CRITICAL(40) + DENY(20) + path(15) + repeat(15) = 90
        assertThat(calc.calculateScore(event, 6L)).isEqualTo(90);
    }

    @Test
    void composesTheFourProductionRulesWithoutRepeatOffender() {
        MiniWsaProperties props = TestProperties.pdfDefaults();
        ThreatScoreCalculator calc = new ThreatScoreCalculator(List.of(
                new SeverityEvaluationRule(props),
                new ActionEvaluationRule(props),
                new SensitivePathEvaluationRule(props),
                new RepeatOffenderEvaluationRule(props)),
                props);

        SecurityEventDto event = TestFixtures.event(Severity.MEDIUM, Action.ALERT, "/health");

        // MEDIUM(20) + ALERT(10) + path(0) + repeat(0) = 30
        assertThat(calc.calculateScore(event, 5L)).isEqualTo(30);
    }
}
