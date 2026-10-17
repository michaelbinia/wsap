package com.security.wsa.service.enrichment.rules;

import com.security.wsa.config.MiniWsaProperties;
import com.security.wsa.model.SecurityEventDto;
import com.security.wsa.model.enums.Severity;
import com.security.wsa.service.enrichment.ThreatEvaluationRule;
import org.springframework.stereotype.Component;

import java.util.Map;

@Component
public class SeverityEvaluationRule implements ThreatEvaluationRule {

    private final Map<Severity, Integer> weights;

    public SeverityEvaluationRule(MiniWsaProperties properties) {
        this.weights = properties.scoring().severity();
    }

    @Override
    public int evaluate(SecurityEventDto event, long recentRequestsCountFromIp) {
        return weights.get(event.rule().severity());
    }
}
