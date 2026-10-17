package com.security.wsa.service.enrichment;

import com.security.wsa.config.MiniWsaProperties;
import com.security.wsa.model.SecurityEventDto;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class ThreatScoreCalculator {

    private final List<ThreatEvaluationRule> rules;
    private final int maxScore;

    public ThreatScoreCalculator(List<ThreatEvaluationRule> rules, MiniWsaProperties properties) {
        this.rules = List.copyOf(rules);
        this.maxScore = properties.scoring().maxScore();
    }

    public int calculateScore(SecurityEventDto event, long recentRequestsCountFromIp) {
        int total = 0;
        for (ThreatEvaluationRule rule : rules) {
            total += rule.evaluate(event, recentRequestsCountFromIp);
        }
        return Math.min(total, maxScore);
    }
}
