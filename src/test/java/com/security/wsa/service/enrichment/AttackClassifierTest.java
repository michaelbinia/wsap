package com.security.wsa.service.enrichment;

import com.security.wsa.model.enums.AttackCategory;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import static org.assertj.core.api.Assertions.assertThat;

class AttackClassifierTest {

    private final AttackClassifier classifier = new AttackClassifier();

    @ParameterizedTest
    @CsvSource(delimiter = '|', value = {
            "INJECTION          | SQL/Command Injection",
            "XSS                | Cross-Site Scripting",
            "PROTOCOL_VIOLATION | Protocol Anomaly",
            "DATA_LEAKAGE       | Data Exfiltration",
            "BOT                | Bot Activity",
            "DOS                | Denial of Service",
            "RATE_LIMIT         | Rate Limiting"
    })
    void returnsPdfLabelForEveryCategory(AttackCategory category, String expected) {
        assertThat(classifier.classify(category)).isEqualTo(expected.trim());
    }
}
