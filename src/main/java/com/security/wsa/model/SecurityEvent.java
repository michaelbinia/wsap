package com.security.wsa.model;

import com.security.wsa.model.enums.Action;

import java.time.Instant;

public record SecurityEvent(
        Long id,
        String eventId,
        Instant timestamp,
        Integer configId,
        String policyId,
        String clientIp,
        String hostname,
        String path,
        String method,
        Integer statusCode,
        String userAgent,
        Rule rule,
        Action action,
        GeoLocation geoLocation,
        Long requestSize,
        Long responseSize,
        String attackType,
        int threatScore,
        Instant receivedAt
) {
}
