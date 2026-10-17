package com.security.wsa.model;

import java.util.List;

public record TimeSeriesResponse(
        Integer configId,
        String interval,
        List<TimeSeriesBucket> buckets
) {
}
