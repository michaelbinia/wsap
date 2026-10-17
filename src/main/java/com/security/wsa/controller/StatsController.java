package com.security.wsa.controller;

import com.security.wsa.model.StatsSummaryResponse;
import com.security.wsa.model.TimeSeriesResponse;
import com.security.wsa.service.StatsService;
import com.security.wsa.service.TimeSeriesService;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;

@RestController
@RequestMapping("/v1/stats")
public class StatsController {

    private final StatsService statsService;
    private final TimeSeriesService timeSeriesService;

    public StatsController(StatsService statsService, TimeSeriesService timeSeriesService) {
        this.statsService = statsService;
        this.timeSeriesService = timeSeriesService;
    }

    @GetMapping("/summary")
    public StatsSummaryResponse summary(
            @RequestParam(required = false) Integer configId,
            @RequestParam(required = false) Instant from,
            @RequestParam(required = false) Instant to) {
        return statsService.summary(configId, from, to);
    }

    @GetMapping("/timeseries")
    public TimeSeriesResponse timeseries(
            @RequestParam(required = false) Integer configId,
            @RequestParam(required = false) Instant from,
            @RequestParam(required = false) Instant to,
            @RequestParam String interval) {
        return timeSeriesService.timeseries(configId, from, to, interval);
    }
}
