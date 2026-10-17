package com.security.wsa.service.enrichment;

import com.security.wsa.model.SecurityEventDto;

public interface ThreatEvaluationRule {

    /**
     * Returns the number of points this rule contributes to the threat score.
     *
     * @param event                     the ingested event being scored
     * @param recentRequestsCountFromIp caller-computed count of events from the same
     *                                  {@code clientIp} within the last 10 minutes
     *                                  (per the assignment PDF), excluding the event
     *                                  currently being scored
     * @return a non-negative point contribution
     */
    int evaluate(SecurityEventDto event, long recentRequestsCountFromIp);
}
