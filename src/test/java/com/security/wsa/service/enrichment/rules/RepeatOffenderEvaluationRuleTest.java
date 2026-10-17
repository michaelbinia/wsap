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

class RepeatOffenderEvaluationRuleTest {

    private final RepeatOffenderEvaluationRule rule = new RepeatOffenderEvaluationRule(TestProperties.pdfDefaults());

    @ParameterizedTest
    @CsvSource({
            "0,   0",
            "5,   0",
            "6,   15",
            "100, 15"
    })
    void addsFifteenWhenRecentCountIsStrictlyGreaterThanFive(long recent, int expected) {
        assertThat(rule.evaluate(anyEvent(), recent)).isEqualTo(expected);
    }

    private static SecurityEventDto anyEvent() {
        RuleDto ruleDto = new RuleDto("id", "name", null, Severity.LOW, AttackCategory.INJECTION);
        return new SecurityEventDto(
                "evt-1", Instant.parse("2026-05-20T14:32:10Z"), 1, null,
                "1.1.1.1", "h", "/", "GET", 200, null,
                ruleDto, Action.MONITOR, null, null, null);
    }
}
