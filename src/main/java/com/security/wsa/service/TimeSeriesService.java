package com.security.wsa.service;

import com.security.wsa.model.TimeSeriesBucket;
import com.security.wsa.model.TimeSeriesResponse;
import com.security.wsa.repository.SecurityEventRepository;
import com.security.wsa.repository.StatsFilter;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.List;
import java.util.Set;

@Service
public class TimeSeriesService {

    private static final Set<String> VALID_INTERVALS = Set.of("1m", "5m", "1h");

    private final SecurityEventRepository repository;

    public TimeSeriesService(SecurityEventRepository repository) {
        this.repository = repository;
    }

    public TimeSeriesResponse timeseries(Integer configId, Instant from, Instant to, String interval) {
        if (!VALID_INTERVALS.contains(interval)) {
            throw new IllegalArgumentException("interval must be one of: 1m, 5m, 1h");
        }
        StatsFilter filter = new StatsFilter(configId, from, to);
        List<TimeSeriesBucket> buckets = repository.timeseries(filter, interval);
        return new TimeSeriesResponse(configId, interval, buckets);
    }
}
