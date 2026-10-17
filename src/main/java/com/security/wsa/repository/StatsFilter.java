package com.security.wsa.repository;

import java.time.Instant;

public record StatsFilter(
        Integer configId,
        Instant from,
        Instant to
) {
}
