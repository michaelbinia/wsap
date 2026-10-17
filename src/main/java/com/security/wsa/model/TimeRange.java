package com.security.wsa.model;

import java.time.Instant;

public record TimeRange(
        Instant from,
        Instant to
) {
}
