package com.security.wsa.repository;

import com.security.wsa.model.AttackerStats;
import com.security.wsa.model.CategoryStats;
import com.security.wsa.model.PathStats;
import com.security.wsa.model.SecurityEvent;

import java.time.Instant;
import java.util.List;
import java.util.Map;

public interface SecurityEventRepository {

    SecurityEvent save(SecurityEvent event);

    long countByClientIpSince(String clientIp, Instant threshold);

    long count(StatsFilter filter);

    Map<String, CategoryStats> byCategory(StatsFilter filter);

    Map<String, Long> byAction(StatsFilter filter);

    List<AttackerStats> topAttackers(StatsFilter filter, int limit);

    List<PathStats> topTargetedPaths(StatsFilter filter, int limit);

    List<SecurityEvent> findSamples(SamplesFilter filter);

    long countSamples(SamplesFilter filter);
}
