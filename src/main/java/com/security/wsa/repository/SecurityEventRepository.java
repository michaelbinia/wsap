package com.security.wsa.repository;

import com.security.wsa.model.SecurityEvent;

import java.time.Instant;

public interface SecurityEventRepository {

    SecurityEvent save(SecurityEvent event);

    long countByClientIpSince(String clientIp, Instant threshold);
}
