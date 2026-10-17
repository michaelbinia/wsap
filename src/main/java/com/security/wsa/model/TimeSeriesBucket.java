package com.security.wsa.model;

import java.time.Instant;

public record TimeSeriesBucket(
        Instant start,
        long count
) {
}
