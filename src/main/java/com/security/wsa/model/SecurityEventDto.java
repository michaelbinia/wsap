package com.security.wsa.model;

import com.security.wsa.model.enums.Action;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

import java.time.Instant;

public record SecurityEventDto(
        @NotBlank String eventId,
        @NotNull Instant timestamp,
        @NotNull Integer configId,
        String policyId,
        @NotBlank String clientIp,
        @NotBlank String hostname,
        @NotBlank String path,
        @NotBlank String method,
        @NotNull Integer statusCode,
        String userAgent,
        @NotNull @Valid RuleDto rule,
        @NotNull Action action,
        @Valid GeoLocationDto geoLocation,
        Long requestSize,
        Long responseSize
) {
}
