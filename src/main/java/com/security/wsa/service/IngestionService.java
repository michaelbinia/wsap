package com.security.wsa.service;

import com.security.wsa.config.MiniWsaProperties;
import com.security.wsa.model.GeoLocation;
import com.security.wsa.model.GeoLocationDto;
import com.security.wsa.model.IngestResult;
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

    private final SecurityEventRepository repository;
    private final ThreatScoreCalculator threatScoreCalculator;
    private final AttackClassifier attackClassifier;
    private final Duration repeatOffenderWindow;

    public IngestionService(SecurityEventRepository repository,
                            ThreatScoreCalculator threatScoreCalculator,
                            AttackClassifier attackClassifier,
                            MiniWsaProperties properties) {
        this.repository = repository;
        this.threatScoreCalculator = threatScoreCalculator;
        this.attackClassifier = attackClassifier;
        this.repeatOffenderWindow = properties.scoring().repeatOffender().window();
    }

    public IngestResult ingestOne(SecurityEventDto dto) {
        Instant now = Instant.now();
        Instant from = now.minus(repeatOffenderWindow);
        long recent = repository.countByClientIpInWindow(dto.clientIp(), from, now, dto.eventId());
        int threatScore = threatScoreCalculator.calculateScore(dto, recent);
        String attackType = attackClassifier.classify(dto.rule().category());

        SecurityEvent toSave = new SecurityEvent(
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
                now);

        SecurityEvent after = repository.save(toSave);
        if (after.id() == null) {
            SecurityEvent stored = repository.findByEventId(dto.eventId())
                    .orElseThrow(() -> new IllegalStateException(
                            "event_id=" + dto.eventId() + " conflicted but is not findable; "
                                    + "likely a race or missing row — investigate"));
            return new IngestResult(stored, IngestResult.Status.DUPLICATE);
        }
        return new IngestResult(after, IngestResult.Status.CREATED);
    }

    public List<IngestResult> ingestBatch(List<SecurityEventDto> events) {
        List<IngestResult> results = new ArrayList<>(events.size());
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
