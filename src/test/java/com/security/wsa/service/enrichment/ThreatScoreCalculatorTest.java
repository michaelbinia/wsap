package com.security.wsa.service.enrichment;

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
        ThreatScoreCalculator calc = new ThreatScoreCalculator(List.of(
                (event, count) -> 10,
                (event, count) -> 25,
                (event, count) -> 5));

        int score = calc.calculateScore(TestFixtures.event(Severity.LOW, Action.MONITOR, "/"), 0L);

        assertThat(score).isEqualTo(40);
    }

    @Test
    void capsScoreAt100() {
        ThreatScoreCalculator calc = new ThreatScoreCalculator(List.of(
                (event, count) -> 60,
                (event, count) -> 50,
                (event, count) -> 30));

        int score = calc.calculateScore(TestFixtures.event(Severity.LOW, Action.MONITOR, "/"), 0L);

        assertThat(score).isEqualTo(100);
    }

    @Test
    void returnsZeroWhenNoRulesAreRegistered() {
        ThreatScoreCalculator calc = new ThreatScoreCalculator(List.of());

        int score = calc.calculateScore(TestFixtures.event(Severity.CRITICAL, Action.DENY, "/admin/login"), 100L);

        assertThat(score).isZero();
    }

    @Test
    void composesTheFourProductionRulesForTheWorstCaseEvent() {
        ThreatScoreCalculator calc = new ThreatScoreCalculator(List.of(
                new SeverityEvaluationRule(),
                new ActionEvaluationRule(),
                new SensitivePathEvaluationRule(),
                new RepeatOffenderEvaluationRule()));

        SecurityEventDto event = TestFixtures.event(Severity.CRITICAL, Action.DENY, "/api/v1/admin/login");

        // CRITICAL(40) + DENY(20) + path(15) + repeat(15) = 90
        assertThat(calc.calculateScore(event, 6L)).isEqualTo(90);
    }

    @Test
    void composesTheFourProductionRulesWithoutRepeatOffender() {
        ThreatScoreCalculator calc = new ThreatScoreCalculator(List.of(
                new SeverityEvaluationRule(),
                new ActionEvaluationRule(),
                new SensitivePathEvaluationRule(),
                new RepeatOffenderEvaluationRule()));

        SecurityEventDto event = TestFixtures.event(Severity.MEDIUM, Action.ALERT, "/health");

        // MEDIUM(20) + ALERT(10) + path(0) + repeat(0) = 30
        assertThat(calc.calculateScore(event, 5L)).isEqualTo(30);
    }
}
