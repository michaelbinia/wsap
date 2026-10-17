CREATE INDEX idx_events_client_ip_received_at
    ON security_events (client_ip, received_at);
