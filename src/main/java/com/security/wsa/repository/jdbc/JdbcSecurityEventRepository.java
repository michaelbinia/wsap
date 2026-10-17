package com.security.wsa.repository.jdbc;

import com.security.wsa.model.AttackerStats;
import com.security.wsa.model.CategoryStats;
import com.security.wsa.model.GeoLocation;
import com.security.wsa.model.PathStats;
import com.security.wsa.model.Rule;
import com.security.wsa.model.SecurityEvent;
import com.security.wsa.model.TimeSeriesBucket;
import com.security.wsa.model.enums.Action;
import com.security.wsa.model.enums.AttackCategory;
import com.security.wsa.model.enums.Severity;
import com.security.wsa.repository.SamplesFilter;
import com.security.wsa.repository.SecurityEventRepository;
import com.security.wsa.repository.StatsFilter;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;

import java.sql.Timestamp;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@Repository
public class JdbcSecurityEventRepository implements SecurityEventRepository {

    private static final String FILTER_CLAUSE = """
             WHERE (CAST(:configId AS integer)      IS NULL OR config_id = :configId)
               AND (CAST(:fromTs   AS timestamptz) IS NULL OR timestamp >= :fromTs)
               AND (CAST(:toTs     AS timestamptz) IS NULL OR timestamp <= :toTs)
            """;

    private static final String SAMPLES_WHERE = """
             WHERE (CAST(:configId AS integer)      IS NULL OR config_id     = :configId)
               AND (CAST(:fromTs   AS timestamptz)  IS NULL OR timestamp    >= :fromTs)
               AND (CAST(:toTs     AS timestamptz)  IS NULL OR timestamp    <= :toTs)
               AND (CAST(:category AS text)         IS NULL OR rule_category = :category)
               AND (CAST(:action   AS text)         IS NULL OR action        = :action)
            """;

    private static final RowMapper<SecurityEvent> ROW = (rs, rowNum) -> new SecurityEvent(
            rs.getLong("id"),
            rs.getString("event_id"),
            rs.getTimestamp("timestamp").toInstant(),
            rs.getInt("config_id"),
            rs.getString("policy_id"),
            rs.getString("client_ip"),
            rs.getString("hostname"),
            rs.getString("path"),
            rs.getString("method"),
            rs.getInt("status_code"),
            rs.getString("user_agent"),
            new Rule(
                    rs.getString("rule_id"),
                    rs.getString("rule_name"),
                    rs.getString("rule_message"),
                    Severity.valueOf(rs.getString("rule_severity")),
                    AttackCategory.valueOf(rs.getString("rule_category"))),
            Action.valueOf(rs.getString("action")),
            rs.getString("geo_country") != null
                    ? new GeoLocation(rs.getString("geo_country"), rs.getString("geo_city"))
                    : null,
            (Long) rs.getObject("request_size"),
            (Long) rs.getObject("response_size"),
            rs.getString("attack_type"),
            rs.getInt("threat_score"),
            rs.getTimestamp("received_at").toInstant());

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

    @Override
    public long count(StatsFilter filter) {
        return bindFilter(jdbc.sql("SELECT COUNT(*) FROM security_events" + FILTER_CLAUSE), filter)
                .query(Long.class).single();
    }

    @Override
    public Map<String, CategoryStats> byCategory(StatsFilter filter) {
        return bindFilter(jdbc.sql("""
                        SELECT rule_category                      AS category,
                               COUNT(*)                           AS count,
                               AVG(threat_score)::numeric(5,1)    AS avg_threat_score
                          FROM security_events""" + FILTER_CLAUSE + """
                         GROUP BY rule_category
                        """), filter)
                .query((rs, rowNum) -> Map.entry(
                        rs.getString("category"),
                        new CategoryStats(rs.getLong("count"), rs.getDouble("avg_threat_score"))))
                .list()
                .stream()
                .collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue));
    }

    @Override
    public Map<String, Long> byAction(StatsFilter filter) {
        return bindFilter(jdbc.sql("""
                        SELECT action, COUNT(*) AS count
                          FROM security_events""" + FILTER_CLAUSE + """
                         GROUP BY action
                        """), filter)
                .query((rs, rowNum) -> Map.entry(rs.getString("action"), rs.getLong("count")))
                .list()
                .stream()
                .collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue));
    }

    @Override
    public List<AttackerStats> topAttackers(StatsFilter filter, int limit) {
        return bindFilter(jdbc.sql("""
                        SELECT HOST(client_ip)                    AS client_ip,
                               COUNT(*)                           AS count,
                               AVG(threat_score)::numeric(5,1)    AS avg_threat_score
                          FROM security_events""" + FILTER_CLAUSE + """
                         GROUP BY client_ip
                         ORDER BY count DESC
                         LIMIT :limit
                        """), filter)
                .param("limit", limit)
                .query((rs, rowNum) -> new AttackerStats(
                        rs.getString("client_ip"),
                        rs.getLong("count"),
                        rs.getDouble("avg_threat_score")))
                .list();
    }

    @Override
    public List<PathStats> topTargetedPaths(StatsFilter filter, int limit) {
        return bindFilter(jdbc.sql("""
                        SELECT path, COUNT(*) AS count
                          FROM security_events""" + FILTER_CLAUSE + """
                         GROUP BY path
                         ORDER BY count DESC
                         LIMIT :limit
                        """), filter)
                .param("limit", limit)
                .query((rs, rowNum) -> new PathStats(rs.getString("path"), rs.getLong("count")))
                .list();
    }

    @Override
    public List<SecurityEvent> findSamples(SamplesFilter filter) {
        return bindSamplesFilter(jdbc.sql("SELECT * FROM security_events" + SAMPLES_WHERE + """
                         ORDER BY timestamp DESC
                         LIMIT :limit OFFSET :offset
                        """), filter)
                .param("limit", filter.limit())
                .param("offset", filter.offset())
                .query(ROW)
                .list();
    }

    @Override
    public long countSamples(SamplesFilter filter) {
        return bindSamplesFilter(jdbc.sql("SELECT COUNT(*) FROM security_events" + SAMPLES_WHERE), filter)
                .query(Long.class).single();
    }

    @Override
    public List<TimeSeriesBucket> timeseries(StatsFilter filter, String interval) {
        String bucketExpr = switch (interval) {
            case "1m" -> "date_trunc('minute', timestamp)";
            case "1h" -> "date_trunc('hour', timestamp)";
            case "5m" -> "to_timestamp(FLOOR(EXTRACT(EPOCH FROM timestamp) / 300) * 300)";
            default -> throw new IllegalArgumentException("interval must be one of: 1m, 5m, 1h");
        };
        String sql = "SELECT " + bucketExpr + " AS bucket, COUNT(*) AS count "
                + "FROM security_events" + FILTER_CLAUSE
                + " GROUP BY bucket ORDER BY bucket";
        return bindFilter(jdbc.sql(sql), filter)
                .query((rs, rowNum) -> new TimeSeriesBucket(
                        rs.getTimestamp("bucket").toInstant(),
                        rs.getLong("count")))
                .list();
    }

    private static JdbcClient.StatementSpec bindFilter(JdbcClient.StatementSpec spec, StatsFilter f) {
        return spec
                .param("configId", f.configId())
                .param("fromTs", f.from() != null ? Timestamp.from(f.from()) : null)
                .param("toTs", f.to() != null ? Timestamp.from(f.to()) : null);
    }

    private static JdbcClient.StatementSpec bindSamplesFilter(JdbcClient.StatementSpec spec, SamplesFilter f) {
        return spec
                .param("configId", f.configId())
                .param("fromTs", f.from() != null ? Timestamp.from(f.from()) : null)
                .param("toTs", f.to() != null ? Timestamp.from(f.to()) : null)
                .param("category", f.category() != null ? f.category().name() : null)
                .param("action", f.action() != null ? f.action().name() : null);
    }
}
