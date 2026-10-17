package com.security.wsa.config;

import com.security.wsa.model.enums.Action;
import com.security.wsa.model.enums.Severity;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.PositiveOrZero;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

import java.time.Duration;
import java.util.EnumSet;
import java.util.List;
import java.util.Map;

@ConfigurationProperties(prefix = "mini-wsa")
@Validated
public record MiniWsaProperties(
        @Valid @NotNull Stats stats,
        @Valid @NotNull Samples samples,
        @Valid @NotNull Scoring scoring
) {

    public record Stats(@Min(1) int topN) {
    }

    public record Samples(
            @Min(1) int defaultLimit,
            @Min(1) int maxLimit
    ) {
        public Samples {
            if (maxLimit < defaultLimit) {
                throw new IllegalArgumentException(
                        "maxLimit (" + maxLimit + ") must be >= defaultLimit (" + defaultLimit + ")");
            }
        }
    }

    public record Scoring(
            @Min(1) @Max(1000) int maxScore,
            @NotNull Map<Severity, @NotNull @PositiveOrZero Integer> severity,
            @NotNull Map<Action, @NotNull @PositiveOrZero Integer> action,
            @Valid @NotNull SensitivePath sensitivePath,
            @Valid @NotNull RepeatOffender repeatOffender
    ) {
        public Scoring {
            if (!severity.keySet().containsAll(EnumSet.allOf(Severity.class))) {
                throw new IllegalArgumentException(
                        "scoring.severity must map all Severity values; got " + severity.keySet());
            }
            if (!action.keySet().containsAll(EnumSet.allOf(Action.class))) {
                throw new IllegalArgumentException(
                        "scoring.action must map all Action values; got " + action.keySet());
            }
        }

        public record SensitivePath(
                @PositiveOrZero int bonus,
                @NotEmpty List<@NotBlank String> markers
        ) {
        }

        public record RepeatOffender(
                @PositiveOrZero int bonus,
                @PositiveOrZero int threshold,
                @NotNull Duration window
        ) {
        }
    }
}
