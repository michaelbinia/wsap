package com.security.wsa.service;

import java.time.Instant;

public final class TimeRanges {

    private TimeRanges() {
    }

    public static void requireFromBeforeTo(Instant from, Instant to) {
        if (from != null && to != null && from.isAfter(to)) {
            throw new IllegalArgumentException(
                    "'from' (" + from + ") must be <= 'to' (" + to + ")");
        }
    }
}
