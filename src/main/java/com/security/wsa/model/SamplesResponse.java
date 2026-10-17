package com.security.wsa.model;

import java.util.List;

public record SamplesResponse(
        long total,
        List<SecurityEvent> events
) {
}
