package com.security.wsa.model;

public record AttackerStats(
        String clientIp,
        long count,
        double avgThreatScore
) {
}
