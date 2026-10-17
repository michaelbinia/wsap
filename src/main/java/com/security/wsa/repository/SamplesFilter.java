package com.security.wsa.repository;

import com.security.wsa.model.enums.Action;
import com.security.wsa.model.enums.AttackCategory;

import java.time.Instant;

public record SamplesFilter(
        Integer configId,
        Instant from,
        Instant to,
        AttackCategory category,
        Action action,
        int limit,
        int offset
) {
}
