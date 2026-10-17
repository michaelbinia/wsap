package com.security.wsa.service.enrichment.rules;

import com.security.wsa.config.MiniWsaProperties;
import com.security.wsa.model.SecurityEventDto;
import com.security.wsa.service.enrichment.ThreatEvaluationRule;
import org.springframework.stereotype.Component;

@Component
public class RepeatOffenderEvaluationRule implements ThreatEvaluationRule {

    private final int threshold;
    private final int bonus;

    public RepeatOffenderEvaluationRule(MiniWsaProperties properties) {
        this.threshold = properties.scoring().repeatOffender().threshold();
        this.bonus = properties.scoring().repeatOffender().bonus();
    }

    @Override
    public int evaluate(SecurityEventDto event, long recentRequestsCountFromIp) {
        return recentRequestsCountFromIp > threshold ? bonus : 0;
    }
}
