package com.security.wsa.service.enrichment.rules;

import com.security.wsa.model.SecurityEventDto;
import com.security.wsa.service.enrichment.ThreatEvaluationRule;
import org.springframework.stereotype.Component;

@Component
public class RepeatOffenderEvaluationRule implements ThreatEvaluationRule {

    @Override
    public int evaluate(SecurityEventDto event, long recentRequestsCountFromIp) {
        return recentRequestsCountFromIp > 5 ? 15 : 0;
    }
}
