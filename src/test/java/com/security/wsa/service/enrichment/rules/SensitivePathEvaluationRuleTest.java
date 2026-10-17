package com.security.wsa.service.enrichment.rules;

import com.security.wsa.model.RuleDto;
import com.security.wsa.model.SecurityEventDto;
import com.security.wsa.model.enums.Action;
import com.security.wsa.model.enums.AttackCategory;
import com.security.wsa.model.enums.Severity;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;

class SensitivePathEvaluationRuleTest {

    private final SensitivePathEvaluationRule rule = new SensitivePathEvaluationRule();

    @ParameterizedTest
    @ValueSource(strings = {
            "/admin",
            "/api/admin/users",
            "/login",
            "/api/v1/login",
            "/admin/login"
    })
    void addsFifteenWhenPathContainsAdminOrLogin(String path) {
        assertThat(rule.evaluate(eventWithPath(path), 0L)).isEqualTo(15);
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "/",
            "/api/v1/users",
            "/health",
            "/public/index.html"
    })
    void addsZeroWhenPathHasNeitherSubstring(String path) {
        assertThat(rule.evaluate(eventWithPath(path), 0L)).isZero();
    }

    @Test
    void matchIsCaseSensitive() {
        assertThat(rule.evaluate(eventWithPath("/Admin"), 0L)).isZero();
        assertThat(rule.evaluate(eventWithPath("/LOGIN"), 0L)).isZero();
    }

    private static SecurityEventDto eventWithPath(String path) {
        RuleDto ruleDto = new RuleDto("id", "name", null, Severity.LOW, AttackCategory.INJECTION);
        return new SecurityEventDto(
                "evt-1", Instant.parse("2026-05-20T14:32:10Z"), 1, null,
                "1.1.1.1", "h", path, "GET", 200, null,
                ruleDto, Action.MONITOR, null, null, null);
    }
}
