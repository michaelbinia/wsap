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

class ActionEvaluationRuleTest {

    private final ActionEvaluationRule rule = new ActionEvaluationRule(TestProperties.pdfDefaults());

    @ParameterizedTest
    @CsvSource({
            "DENY,    20",
            "ALERT,   10",
            "MONITOR, 0"
    })
    void scoresEachActionPerPdf(Action action, int expected) {
        assertThat(rule.evaluate(eventWithAction(action), 0L)).isEqualTo(expected);
    }

    private static SecurityEventDto eventWithAction(Action action) {
        RuleDto ruleDto = new RuleDto("id", "name", null, Severity.LOW, AttackCategory.INJECTION);
        return new SecurityEventDto(
                "evt-1", Instant.parse("2026-05-20T14:32:10Z"), 1, null,
                "1.1.1.1", "h", "/", "GET", 200, null,
                ruleDto, action, null, null, null);
    }
}
