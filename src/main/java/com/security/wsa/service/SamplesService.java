package com.security.wsa.service;

import com.security.wsa.model.SamplesResponse;
import com.security.wsa.model.SecurityEvent;
import com.security.wsa.model.enums.Action;
import com.security.wsa.model.enums.AttackCategory;
import com.security.wsa.repository.SamplesFilter;
import com.security.wsa.repository.SecurityEventRepository;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.List;

@Service
public class SamplesService {

    private final SecurityEventRepository repository;

    public SamplesService(SecurityEventRepository repository) {
        this.repository = repository;
    }

    public SamplesResponse search(Integer configId, Instant from, Instant to,
                                  AttackCategory category, Action action,
                                  int limit, int offset) {
        TimeRanges.requireFromBeforeTo(from, to);
        SamplesFilter filter = new SamplesFilter(configId, from, to, category, action, limit, offset);
        long total = repository.countSamples(filter);
        List<SecurityEvent> events = repository.findSamples(filter);
        return new SamplesResponse(total, events);
    }
}
