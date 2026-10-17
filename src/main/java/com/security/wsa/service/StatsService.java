package com.security.wsa.service;

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

    private static final int TOP_N = 10;

    private final SecurityEventRepository repository;

    public StatsService(SecurityEventRepository repository) {
        this.repository = repository;
    }

    public StatsSummaryResponse summary(Integer configId, Instant from, Instant to) {
        StatsFilter filter = new StatsFilter(configId, from, to);

        long total = repository.count(filter);
        Map<String, CategoryStats> byCategory = repository.byCategory(filter);
        Map<String, Long> byAction = repository.byAction(filter);
        List<AttackerStats> topAttackers = repository.topAttackers(filter, TOP_N);
        List<PathStats> topTargetedPaths = repository.topTargetedPaths(filter, TOP_N);

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
