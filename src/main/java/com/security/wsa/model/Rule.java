package com.security.wsa.model;

import com.security.wsa.model.enums.AttackCategory;
import com.security.wsa.model.enums.Severity;

public record Rule(
        String id,
        String name,
        String message,
        Severity severity,
        AttackCategory category
) {
}
