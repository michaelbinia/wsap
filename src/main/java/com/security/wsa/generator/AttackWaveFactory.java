package com.security.wsa.generator;

import com.security.wsa.model.SecurityEventDto;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;

public class AttackWaveFactory {

    private static final Duration WAVE_WINDOW = Duration.ofMinutes(2);

    private final RandomEventFactory eventFactory;
    private final Random random;

    public AttackWaveFactory(RandomEventFactory eventFactory, Random random) {
        this.eventFactory = eventFactory;
        this.random = random;
    }

    /**
     * Produces a burst of {@code size} events that share the same {@code clientIp} and
     * {@code path}, with timestamps packed inside a two-minute window ending at {@code endTimestamp}.
     * Triggers the repeat-offender bonus when {@code size > 6}.
     */
    public List<SecurityEventDto> wave(int size, Instant endTimestamp) {
        String clientIp = pick(RandomEventFactory.ipPool());
        String path = pick(RandomEventFactory.paths());
        long windowMillis = WAVE_WINDOW.toMillis();
        List<SecurityEventDto> events = new ArrayList<>(size);
        for (int i = 0; i < size; i++) {
            long offsetMillis = (long) ((double) i / Math.max(size - 1, 1) * windowMillis);
            Instant timestamp = endTimestamp.minusMillis(windowMillis - offsetMillis);
            events.add(eventFactory.build(timestamp, clientIp, path));
        }
        return events;
    }

    private <T> T pick(List<T> list) {
        return list.get(random.nextInt(list.size()));
    }
}
