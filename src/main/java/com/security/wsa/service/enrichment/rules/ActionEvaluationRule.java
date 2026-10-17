package com.security.wsa.service.enrichment.rules;

import com.security.wsa.model.SecurityEventDto;
import com.security.wsa.service.enrichment.ThreatEvaluationRule;
import org.springframework.stereotype.Component;

@Component
public class ActionEvaluationRule implements ThreatEvaluationRule {

    @Override
    public int evaluate(SecurityEventDto event, long recentRequestsCountFromIp) {
        return switch (event.action()) {
            case DENY -> 20;
            case ALERT -> 10;
            case MONITOR -> 0;
        };
    }
}
