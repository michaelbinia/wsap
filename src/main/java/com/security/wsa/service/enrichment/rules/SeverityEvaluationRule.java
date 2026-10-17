package com.security.wsa.service.enrichment.rules;

import com.security.wsa.model.SecurityEventDto;
import com.security.wsa.service.enrichment.ThreatEvaluationRule;
import org.springframework.stereotype.Component;

@Component
public class SeverityEvaluationRule implements ThreatEvaluationRule {

    @Override
    public int evaluate(SecurityEventDto event, long recentRequestsCountFromIp) {
        return switch (event.rule().severity()) {
            case CRITICAL -> 40;
            case HIGH -> 30;
            case MEDIUM -> 20;
            case LOW -> 10;
        };
    }
}
