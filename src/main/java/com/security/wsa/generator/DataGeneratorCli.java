package com.security.wsa.generator;

import com.security.wsa.model.SecurityEventDto;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Profile;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientResponseException;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Random;

@Component
@Profile("generator")
public class DataGeneratorCli implements CommandLineRunner {

    private static final Logger log = LoggerFactory.getLogger(DataGeneratorCli.class);

    private static final String ARG_COUNT = "count";
    private static final String ARG_WAVES = "waves";
    private static final String ARG_WAVE_SIZE = "wave-size";
    private static final String ARG_TARGET = "target";
    private static final String ARG_BATCH = "batch";
    private static final String ARG_SEED = "seed";

    private static final int DEFAULT_COUNT = 10_000;
    private static final int DEFAULT_WAVES = 10;
    private static final int DEFAULT_WAVE_SIZE = 50;
    private static final String DEFAULT_TARGET = "http://localhost:8080/v1/events/ingest";
    private static final int DEFAULT_BATCH = 100;
    private static final long DEFAULT_SEED = 42L;

    private static final int WINDOW_SECONDS = 3600;

    private final ApplicationArguments appArgs;

    public DataGeneratorCli(ApplicationArguments appArgs) {
        this.appArgs = appArgs;
    }

    @Override
    public void run(String... args) {
        int count = intArg(ARG_COUNT, DEFAULT_COUNT);
        int waves = intArg(ARG_WAVES, DEFAULT_WAVES);
        int waveSize = intArg(ARG_WAVE_SIZE, DEFAULT_WAVE_SIZE);
        String target = stringArg(ARG_TARGET, DEFAULT_TARGET);
        int batchSize = intArg(ARG_BATCH, DEFAULT_BATCH);
        long seed = longArg(ARG_SEED, DEFAULT_SEED);

        int waveTotal = waves * waveSize;
        if (waveTotal > count) {
            throw new IllegalArgumentException(
                    "waves * wave-size (" + waveTotal + ") must not exceed count (" + count + ")");
        }
        int normalCount = count - waveTotal;

        log.info("Generating count={} ({} normal + {} wave events across {} waves of {}), target={}",
                count, normalCount, waveTotal, waves, waveSize, target);

        Random random = new Random(seed);
        RandomEventFactory factory = new RandomEventFactory(random);
        AttackWaveFactory waveFactory = new AttackWaveFactory(factory, random);

        List<SecurityEventDto> events = new ArrayList<>(count);
        for (int i = 0; i < normalCount; i++) {
            events.add(factory.next(WINDOW_SECONDS));
        }
        Instant now = Instant.now();
        for (int i = 0; i < waves; i++) {
            events.addAll(waveFactory.wave(waveSize, now.minusSeconds((long) i * 30)));
        }
        Collections.shuffle(events, random);

        RestClient client = RestClient.create();
        long start = System.currentTimeMillis();
        int sent = 0;
        int rejected = 0;
        for (int i = 0; i < events.size(); i += batchSize) {
            List<SecurityEventDto> batch = events.subList(i, Math.min(i + batchSize, events.size()));
            try {
                client.post()
                        .uri(target)
                        .contentType(MediaType.APPLICATION_JSON)
                        .body(batch)
                        .retrieve()
                        .toBodilessEntity();
                sent += batch.size();
            } catch (RestClientResponseException e) {
                rejected += batch.size();
                log.warn("Batch of {} rejected: {} {}", batch.size(), e.getStatusCode(), e.getResponseBodyAsString());
            } catch (Exception e) {
                rejected += batch.size();
                log.warn("Batch of {} failed: {}", batch.size(), e.getMessage());
            }
        }
        long elapsedMs = System.currentTimeMillis() - start;
        log.info("Generator complete: sent={} rejected={} elapsedMs={}", sent, rejected, elapsedMs);
    }

    private int intArg(String name, int defaultValue) {
        List<String> values = appArgs.getOptionValues(name);
        return (values == null || values.isEmpty()) ? defaultValue : Integer.parseInt(values.get(0));
    }

    private long longArg(String name, long defaultValue) {
        List<String> values = appArgs.getOptionValues(name);
        return (values == null || values.isEmpty()) ? defaultValue : Long.parseLong(values.get(0));
    }

    private String stringArg(String name, String defaultValue) {
        List<String> values = appArgs.getOptionValues(name);
        return (values == null || values.isEmpty()) ? defaultValue : values.get(0);
    }
}
