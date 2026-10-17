package com.security.wsa.model;

import com.security.wsa.model.enums.AttackCategory;
import com.security.wsa.model.enums.Severity;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

public record RuleDto(
        @NotBlank String id,
        @NotBlank String name,
        String message,
        @NotNull Severity severity,
        @NotNull AttackCategory category
) {
}
