CREATE TABLE security_events (
    id              BIGSERIAL        PRIMARY KEY,
    event_id        VARCHAR(64)      NOT NULL,
    timestamp       TIMESTAMPTZ      NOT NULL,
    config_id       INTEGER          NOT NULL,
    policy_id       VARCHAR(64),
    client_ip       INET             NOT NULL,
    hostname        VARCHAR(255)     NOT NULL,
    path            VARCHAR(1024)    NOT NULL,
    method          VARCHAR(16)      NOT NULL,
    status_code     INTEGER          NOT NULL,
    user_agent      VARCHAR(512),
    rule_id         VARCHAR(64)      NOT NULL,
    rule_name       VARCHAR(255)     NOT NULL,
    rule_message    VARCHAR(1024),
    rule_severity   VARCHAR(16)      NOT NULL,
    rule_category   VARCHAR(32)      NOT NULL,
    action          VARCHAR(16)      NOT NULL,
    geo_country     VARCHAR(64),
    geo_city        VARCHAR(128),
    request_size    BIGINT,
    response_size   BIGINT,
    attack_type     VARCHAR(64)      NOT NULL,
    threat_score    INTEGER          NOT NULL,
    received_at     TIMESTAMPTZ      NOT NULL,

    CONSTRAINT uq_security_events_event_id UNIQUE (event_id)
);

CREATE INDEX idx_events_config_timestamp
    ON security_events (config_id, timestamp DESC);

CREATE INDEX idx_events_client_ip_timestamp
    ON security_events (client_ip, timestamp);

CREATE INDEX idx_events_rule_category
    ON security_events (rule_category);

CREATE INDEX idx_events_action
    ON security_events (action);
