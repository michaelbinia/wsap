package com.security.wsa.service;

import com.security.wsa.model.GeoLocation;
import com.security.wsa.model.GeoLocationDto;
import com.security.wsa.model.Rule;
import com.security.wsa.model.RuleDto;
import com.security.wsa.model.SecurityEvent;
import com.security.wsa.model.SecurityEventDto;
import com.security.wsa.repository.SecurityEventRepository;
import com.security.wsa.service.enrichment.AttackClassifier;
import com.security.wsa.service.enrichment.ThreatScoreCalculator;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

@Service
public class IngestionService {

    private static final Duration REPEAT_OFFENDER_WINDOW = Duration.ofMinutes(10);

    private final SecurityEventRepository repository;
    private final ThreatScoreCalculator threatScoreCalculator;
    private final AttackClassifier attackClassifier;

    public IngestionService(SecurityEventRepository repository,
                            ThreatScoreCalculator threatScoreCalculator,
                            AttackClassifier attackClassifier) {
        this.repository = repository;
        this.threatScoreCalculator = threatScoreCalculator;
        this.attackClassifier = attackClassifier;
    }

    public SecurityEvent ingestOne(SecurityEventDto dto) {
        Instant threshold = dto.timestamp().minus(REPEAT_OFFENDER_WINDOW);
        long recent = repository.countByClientIpSince(dto.clientIp(), threshold);
        int threatScore = threatScoreCalculator.calculateScore(dto, recent);
        String attackType = attackClassifier.classify(dto.rule().category());

        SecurityEvent event = new SecurityEvent(
                null,
                dto.eventId(),
                dto.timestamp(),
                dto.configId(),
                dto.policyId(),
                dto.clientIp(),
                dto.hostname(),
                dto.path(),
                dto.method(),
                dto.statusCode(),
                dto.userAgent(),
                toRule(dto.rule()),
                dto.action(),
                toGeoLocation(dto.geoLocation()),
                dto.requestSize(),
                dto.responseSize(),
                attackType,
                threatScore,
                Instant.now());

        return repository.save(event);
    }

    public List<SecurityEvent> ingestBatch(List<SecurityEventDto> events) {
        List<SecurityEvent> results = new ArrayList<>(events.size());
        for (SecurityEventDto dto : events) {
            results.add(ingestOne(dto));
        }
        return results;
    }

    private static Rule toRule(RuleDto dto) {
        return new Rule(dto.id(), dto.name(), dto.message(), dto.severity(), dto.category());
    }

    private static GeoLocation toGeoLocation(GeoLocationDto dto) {
        if (dto == null) {
            return null;
        }
        return new GeoLocation(dto.country(), dto.city());
    }
}
