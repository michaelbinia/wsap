package com.security.wsa.service.enrichment.rules;

import com.security.wsa.model.SecurityEventDto;
import com.security.wsa.service.enrichment.ThreatEvaluationRule;
import org.springframework.stereotype.Component;

@Component
public class SensitivePathEvaluationRule implements ThreatEvaluationRule {

    @Override
    public int evaluate(SecurityEventDto event, long recentRequestsCountFromIp) {
        String path = event.path();
        return (path.contains("/admin") || path.contains("/login")) ? 15 : 0;
    }
}
