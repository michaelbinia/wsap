package com.security.wsa.generator;

import com.security.wsa.model.GeoLocationDto;
import com.security.wsa.model.RuleDto;
import com.security.wsa.model.SecurityEventDto;
import com.security.wsa.model.enums.Action;
import com.security.wsa.model.enums.AttackCategory;
import com.security.wsa.model.enums.Severity;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;
import java.util.concurrent.atomic.AtomicLong;

public class RandomEventFactory {

    private static final List<Integer> CONFIG_IDS = List.of(14227, 14228, 14229);
    private static final List<String> HOSTNAMES = List.of(
            "www.example.com", "api.example.com", "admin.example.com");
    private static final List<String> PATHS = List.of(
            "/api/v1/login", "/admin", "/", "/api/v1/users", "/search", "/checkout");
    private static final List<String> METHODS = List.of("GET", "POST", "PUT");
    private static final List<Integer> STATUS_CODES = List.of(200, 400, 401, 403, 429, 500);
    private static final List<String> USER_AGENTS = List.of(
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
            "curl/8.4.0",
            "GoogleBot/2.1 (+http://www.google.com/bot.html)",
            "python-requests/2.31");
    private static final List<GeoLocationDto> GEOS = List.of(
            new GeoLocationDto("US", "San Francisco"),
            new GeoLocationDto("CN", "Beijing"),
            new GeoLocationDto("RU", "Moscow"),
            new GeoLocationDto("BR", "Sao Paulo"),
            new GeoLocationDto("DE", "Berlin"),
            new GeoLocationDto("IN", "Bangalore"),
            new GeoLocationDto("GB", "London"),
            new GeoLocationDto("JP", "Tokyo"));

    private static final List<String> IP_POOL = buildIpPool();

    private final Random random;
    private final AtomicLong counter = new AtomicLong(0);

    public RandomEventFactory(Random random) {
        this.random = random;
    }

    /** Returns an event timestamped within {@code windowSeconds} before now. */
    public SecurityEventDto next(int windowSeconds) {
        Instant timestamp = Instant.now().minusSeconds(random.nextInt(Math.max(windowSeconds, 1)));
        return build(timestamp, pick(IP_POOL), pick(PATHS));
    }

    public SecurityEventDto build(Instant timestamp, String clientIp, String path) {
        AttackCategory category = pick(AttackCategory.values());
        Severity severity = severityFor(category);
        Action action = weightedAction();
        String ruleId = "rule-" + (100 + random.nextInt(900));
        return new SecurityEventDto(
                "evt-" + String.format("%08d", counter.incrementAndGet()),
                timestamp,
                pick(CONFIG_IDS),
                "pol_web" + (1 + random.nextInt(3)),
                clientIp,
                pick(HOSTNAMES),
                path,
                pick(METHODS),
                pick(STATUS_CODES),
                pick(USER_AGENTS),
                new RuleDto(ruleId, category.name() + "_detected",
                        "Rule " + ruleId + " triggered", severity, category),
                action,
                pick(GEOS),
                100L + random.nextInt(10_000),
                100L + random.nextInt(50_000));
    }

    static List<String> ipPool() {
        return IP_POOL;
    }

    static List<String> paths() {
        return PATHS;
    }

    private <T> T pick(List<T> list) {
        return list.get(random.nextInt(list.size()));
    }

    private <T> T pick(T[] array) {
        return array[random.nextInt(array.length)];
    }

    private static Severity severityFor(AttackCategory category) {
        return switch (category) {
            case INJECTION, DATA_LEAKAGE -> Severity.CRITICAL;
            case XSS, DOS -> Severity.HIGH;
            case PROTOCOL_VIOLATION -> Severity.MEDIUM;
            case BOT, RATE_LIMIT -> Severity.LOW;
        };
    }

    private Action weightedAction() {
        int r = random.nextInt(10);
        if (r < 6) {
            return Action.DENY;
        }
        if (r < 9) {
            return Action.ALERT;
        }
        return Action.MONITOR;
    }

    private static List<String> buildIpPool() {
        List<String> ips = new ArrayList<>(50);
        for (int i = 1; i <= 20; i++) {
            ips.add("203.0.113." + i);
        }
        for (int i = 1; i <= 15; i++) {
            ips.add("198.51.100." + i);
        }
        for (int i = 1; i <= 15; i++) {
            ips.add("192.0.2." + i);
        }
        return List.copyOf(ips);
    }
}
