package com.security.wsa.service.enrichment.rules;

import com.security.wsa.config.MiniWsaProperties;
import com.security.wsa.model.SecurityEventDto;
import com.security.wsa.service.enrichment.ThreatEvaluationRule;
import org.springframework.stereotype.Component;

import java.util.List;

@Component
public class SensitivePathEvaluationRule implements ThreatEvaluationRule {

    private final List<String> markers;
    private final int bonus;

    public SensitivePathEvaluationRule(MiniWsaProperties properties) {
        this.markers = properties.scoring().sensitivePath().markers();
        this.bonus = properties.scoring().sensitivePath().bonus();
    }

    @Override
    public int evaluate(SecurityEventDto event, long recentRequestsCountFromIp) {
        String path = event.path();
        return markers.stream().anyMatch(path::contains) ? bonus : 0;
    }
}
