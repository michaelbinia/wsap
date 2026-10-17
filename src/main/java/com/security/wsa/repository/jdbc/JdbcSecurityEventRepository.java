package com.security.wsa.repository.jdbc;

import com.security.wsa.model.SecurityEvent;
import com.security.wsa.repository.SecurityEventRepository;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;

import java.sql.Timestamp;
import java.time.Instant;

@Repository
public class JdbcSecurityEventRepository implements SecurityEventRepository {

    private final JdbcClient jdbc;

    public JdbcSecurityEventRepository(JdbcClient jdbc) {
        this.jdbc = jdbc;
    }

    @Override
    public SecurityEvent save(SecurityEvent e) {
        Long id = jdbc.sql("""
                        INSERT INTO security_events (
                            event_id, timestamp, config_id, policy_id,
                            client_ip, hostname, path, method, status_code, user_agent,
                            rule_id, rule_name, rule_message, rule_severity, rule_category,
                            action, geo_country, geo_city, request_size, response_size,
                            attack_type, threat_score, received_at
                        ) VALUES (
                            :eventId, :timestamp, :configId, :policyId,
                            :clientIp::inet, :hostname, :path, :method, :statusCode, :userAgent,
                            :ruleId, :ruleName, :ruleMessage, :ruleSeverity, :ruleCategory,
                            :action, :geoCountry, :geoCity, :requestSize, :responseSize,
                            :attackType, :threatScore, :receivedAt
                        )
                        ON CONFLICT (event_id) DO NOTHING
                        RETURNING id
                        """)
                .param("eventId", e.eventId())
                .param("timestamp", Timestamp.from(e.timestamp()))
                .param("configId", e.configId())
                .param("policyId", e.policyId())
                .param("clientIp", e.clientIp())
                .param("hostname", e.hostname())
                .param("path", e.path())
                .param("method", e.method())
                .param("statusCode", e.statusCode())
                .param("userAgent", e.userAgent())
                .param("ruleId", e.rule().id())
                .param("ruleName", e.rule().name())
                .param("ruleMessage", e.rule().message())
                .param("ruleSeverity", e.rule().severity().name())
                .param("ruleCategory", e.rule().category().name())
                .param("action", e.action().name())
                .param("geoCountry", e.geoLocation() != null ? e.geoLocation().country() : null)
                .param("geoCity", e.geoLocation() != null ? e.geoLocation().city() : null)
                .param("requestSize", e.requestSize())
                .param("responseSize", e.responseSize())
                .param("attackType", e.attackType())
                .param("threatScore", e.threatScore())
                .param("receivedAt", Timestamp.from(e.receivedAt()))
                .query(Long.class).optional().orElse(null);

        return new SecurityEvent(
                id, e.eventId(), e.timestamp(), e.configId(), e.policyId(),
                e.clientIp(), e.hostname(), e.path(), e.method(), e.statusCode(),
                e.userAgent(), e.rule(), e.action(), e.geoLocation(),
                e.requestSize(), e.responseSize(),
                e.attackType(), e.threatScore(), e.receivedAt());
    }

    @Override
    public long countByClientIpSince(String clientIp, Instant threshold) {
        return jdbc.sql("""
                        SELECT COUNT(*) FROM security_events
                         WHERE client_ip = :clientIp::inet
                           AND timestamp > :threshold
                        """)
                .param("clientIp", clientIp)
                .param("threshold", Timestamp.from(threshold))
                .query(Long.class).single();
    }
}
