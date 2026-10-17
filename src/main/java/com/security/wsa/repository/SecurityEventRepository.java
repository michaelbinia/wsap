package com.security.wsa.repository;

import com.security.wsa.model.AttackerStats;
import com.security.wsa.model.CategoryStats;
import com.security.wsa.model.PathStats;
import com.security.wsa.model.SecurityEvent;
import com.security.wsa.model.TimeSeriesBucket;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;

public interface SecurityEventRepository {

    SecurityEvent save(SecurityEvent event);

    Optional<SecurityEvent> findByEventId(String eventId);

    long countByClientIpInWindow(String clientIp, Instant from, Instant to, String excludeEventId);

    long count(StatsFilter filter);

    Map<String, CategoryStats> byCategory(StatsFilter filter);

    Map<String, Long> byAction(StatsFilter filter);

    List<AttackerStats> topAttackers(StatsFilter filter, int limit);

    List<PathStats> topTargetedPaths(StatsFilter filter, int limit);

    List<SecurityEvent> findSamples(SamplesFilter filter);

    long countSamples(SamplesFilter filter);

    List<TimeSeriesBucket> timeseries(StatsFilter filter, String interval);
}
