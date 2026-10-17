package com.security.wsa.config;

import com.security.wsa.model.enums.Action;
import com.security.wsa.model.enums.Severity;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThatThrownBy;

class MiniWsaPropertiesTest {

    @Test
    void scoringConstructorRejectsIncompleteSeverityMap() {
        assertThatThrownBy(() -> new MiniWsaProperties.Scoring(
                100,
                Map.of(Severity.CRITICAL, 40),
                Map.of(Action.DENY, 20, Action.ALERT, 10, Action.MONITOR, 0),
                new MiniWsaProperties.Scoring.SensitivePath(15, List.of("/admin")),
                new MiniWsaProperties.Scoring.RepeatOffender(15, 5, Duration.ofMinutes(10))))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("severity");
    }

    @Test
    void scoringConstructorRejectsIncompleteActionMap() {
        assertThatThrownBy(() -> new MiniWsaProperties.Scoring(
                100,
                Map.of(Severity.CRITICAL, 40, Severity.HIGH, 30, Severity.MEDIUM, 20, Severity.LOW, 10),
                Map.of(Action.DENY, 20),
                new MiniWsaProperties.Scoring.SensitivePath(15, List.of("/admin")),
                new MiniWsaProperties.Scoring.RepeatOffender(15, 5, Duration.ofMinutes(10))))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("action");
    }

    @Test
    void samplesConstructorRejectsMaxLimitBelowDefaultLimit() {
        assertThatThrownBy(() -> new MiniWsaProperties.Samples(50, 20))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("maxLimit")
                .hasMessageContaining("defaultLimit");
    }
}
