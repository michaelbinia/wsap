package com.security.wsa.service.enrichment;

import com.security.wsa.model.RuleDto;
import com.security.wsa.model.SecurityEventDto;
import com.security.wsa.model.enums.Action;
import com.security.wsa.model.enums.AttackCategory;
import com.security.wsa.model.enums.Severity;

import java.time.Instant;

final class TestFixtures {

    private TestFixtures() {
    }

    static SecurityEventDto event(Severity severity, Action action, String path) {
        RuleDto rule = new RuleDto("950001", "SQL_INJECTION", null, severity, AttackCategory.INJECTION);
        return new SecurityEventDto(
                "evt-1",
                Instant.parse("2026-05-20T14:32:10Z"),
                14227,
                "pol_web1",
                "203.0.113.42",
                "www.example.com",
                path,
                "GET",
                200,
                null,
                rule,
                action,
                null,
                null,
                null);
    }
}
