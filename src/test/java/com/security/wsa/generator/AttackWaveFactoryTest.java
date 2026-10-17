package com.security.wsa.generator;

import com.security.wsa.model.SecurityEventDto;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Random;
import java.util.stream.Collectors;

import static org.assertj.core.api.Assertions.assertThat;

class AttackWaveFactoryTest {

    @Test
    void waveSharesClientIpAndPathAcrossAllEvents() {
        Random random = new Random(42L);
        AttackWaveFactory waves = new AttackWaveFactory(new RandomEventFactory(random), random);
        Instant end = Instant.parse("2026-05-20T14:00:00Z");

        List<SecurityEventDto> burst = waves.wave(10, end);

        assertThat(burst).hasSize(10);
        assertThat(burst.stream().map(SecurityEventDto::clientIp).collect(Collectors.toSet()))
                .hasSize(1);
        assertThat(burst.stream().map(SecurityEventDto::path).collect(Collectors.toSet()))
                .hasSize(1);
    }

    @Test
    void allWaveTimestampsFallWithinTwoMinuteWindowEndingAtGivenInstant() {
        Random random = new Random(99L);
        AttackWaveFactory waves = new AttackWaveFactory(new RandomEventFactory(random), random);
        Instant end = Instant.parse("2026-05-20T14:00:00Z");

        List<SecurityEventDto> burst = waves.wave(20, end);

        Instant windowStart = end.minus(Duration.ofMinutes(2));
        for (SecurityEventDto event : burst) {
            assertThat(event.timestamp())
                    .isAfterOrEqualTo(windowStart)
                    .isBeforeOrEqualTo(end);
        }
    }

    @Test
    void eventIdsWithinAWaveAreUnique() {
        Random random = new Random(5L);
        AttackWaveFactory waves = new AttackWaveFactory(new RandomEventFactory(random), random);

        List<SecurityEventDto> burst = waves.wave(50, Instant.parse("2026-05-20T14:00:00Z"));

        long distinct = burst.stream().map(SecurityEventDto::eventId).distinct().count();
        assertThat(distinct).isEqualTo(50L);
    }
}
