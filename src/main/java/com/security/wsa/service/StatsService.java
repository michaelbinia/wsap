package com.security.wsa.service;

import com.security.wsa.config.MiniWsaProperties;
import com.security.wsa.model.AttackerStats;
import com.security.wsa.model.CategoryStats;
import com.security.wsa.model.PathStats;
import com.security.wsa.model.StatsSummaryResponse;
import com.security.wsa.model.TimeRange;
import com.security.wsa.repository.SecurityEventRepository;
import com.security.wsa.repository.StatsFilter;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.List;
import java.util.Map;

@Service
public class StatsService {

    private final SecurityEventRepository repository;
    private final int topN;

    public StatsService(SecurityEventRepository repository, MiniWsaProperties properties) {
        this.repository = repository;
        this.topN = properties.stats().topN();
    }

    public StatsSummaryResponse summary(Integer configId, Instant from, Instant to) {
        TimeRanges.requireFromBeforeTo(from, to);
        StatsFilter filter = new StatsFilter(configId, from, to);

        long total = repository.count(filter);
        Map<String, CategoryStats> byCategory = repository.byCategory(filter);
        Map<String, Long> byAction = repository.byAction(filter);
        List<AttackerStats> topAttackers = repository.topAttackers(filter, topN);
        List<PathStats> topTargetedPaths = repository.topTargetedPaths(filter, topN);

        return new StatsSummaryResponse(
                configId,
                new TimeRange(from, to),
                total,
                byCategory,
                byAction,
                topAttackers,
                topTargetedPaths);
    }
}
