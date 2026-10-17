package com.security.wsa.model;

import java.util.List;
import java.util.Map;

public record StatsSummaryResponse(
        Integer configId,
        TimeRange timeRange,
        long totalEvents,
        Map<String, CategoryStats> byCategory,
        Map<String, Long> byAction,
        List<AttackerStats> topAttackers,
        List<PathStats> topTargetedPaths
) {
}
