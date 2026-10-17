package com.security.wsa.service.enrichment.rules;

import com.security.wsa.config.MiniWsaProperties;
import com.security.wsa.model.SecurityEventDto;
import com.security.wsa.model.enums.Action;
import com.security.wsa.service.enrichment.ThreatEvaluationRule;
import org.springframework.stereotype.Component;

import java.util.Map;

@Component
public class ActionEvaluationRule implements ThreatEvaluationRule {

    private final Map<Action, Integer> weights;

    public ActionEvaluationRule(MiniWsaProperties properties) {
        this.weights = properties.scoring().action();
    }

    @Override
    public int evaluate(SecurityEventDto event, long recentRequestsCountFromIp) {
        return weights.get(event.action());
    }
}
