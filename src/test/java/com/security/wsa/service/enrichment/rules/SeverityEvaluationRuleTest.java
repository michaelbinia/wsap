package com.security.wsa.service.enrichment.rules;

import com.security.wsa.config.TestProperties;
import com.security.wsa.model.RuleDto;
import com.security.wsa.model.SecurityEventDto;
import com.security.wsa.model.enums.Action;
import com.security.wsa.model.enums.AttackCategory;
import com.security.wsa.model.enums.Severity;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;

class SeverityEvaluationRuleTest {

    private final SeverityEvaluationRule rule = new SeverityEvaluationRule(TestProperties.pdfDefaults());

    @ParameterizedTest
    @CsvSource({
            "CRITICAL, 40",
            "HIGH,     30",
            "MEDIUM,   20",
            "LOW,      10"
    })
    void scoresEachSeverityPerPdf(Severity severity, int expected) {
        assertThat(rule.evaluate(eventWithSeverity(severity), 0L)).isEqualTo(expected);
    }

    private static SecurityEventDto eventWithSeverity(Severity severity) {
        RuleDto ruleDto = new RuleDto("id", "name", null, severity, AttackCategory.INJECTION);
        return new SecurityEventDto(
                "evt-1", Instant.parse("2026-05-20T14:32:10Z"), 1, null,
                "1.1.1.1", "h", "/", "GET", 200, null,
                ruleDto, Action.MONITOR, null, null, null);
    }
}
