package com.security.wsa.config;

import com.security.wsa.model.enums.Action;
import com.security.wsa.model.enums.Severity;

import java.time.Duration;
import java.util.List;
import java.util.Map;

public final class TestProperties {

    private TestProperties() {
    }

    public static MiniWsaProperties pdfDefaults() {
        return new MiniWsaProperties(
                new MiniWsaProperties.Stats(10),
                new MiniWsaProperties.Samples(20, 100),
                new MiniWsaProperties.Scoring(
                        100,
                        Map.of(
                                Severity.CRITICAL, 40,
                                Severity.HIGH, 30,
                                Severity.MEDIUM, 20,
                                Severity.LOW, 10),
                        Map.of(
                                Action.DENY, 20,
                                Action.ALERT, 10,
                                Action.MONITOR, 0),
                        new MiniWsaProperties.Scoring.SensitivePath(15, List.of("/admin", "/login")),
                        new MiniWsaProperties.Scoring.RepeatOffender(15, 5, Duration.ofMinutes(10))));
    }
}
