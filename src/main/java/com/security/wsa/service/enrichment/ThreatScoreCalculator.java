package com.security.wsa.service.enrichment;

import com.security.wsa.model.SecurityEventDto;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class ThreatScoreCalculator {

    private static final int MAX_SCORE = 100;

    private final List<ThreatEvaluationRule> rules;

    public ThreatScoreCalculator(List<ThreatEvaluationRule> rules) {
        this.rules = List.copyOf(rules);
    }

    public int calculateScore(SecurityEventDto event, long recentRequestsCountFromIp) {
        int total = 0;
        for (ThreatEvaluationRule rule : rules) {
            total += rule.evaluate(event, recentRequestsCountFromIp);
        }
        return Math.min(total, MAX_SCORE);
    }
}
