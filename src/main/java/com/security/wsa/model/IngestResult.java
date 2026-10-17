package com.security.wsa.model;

public record IngestResult(SecurityEvent event, Status status) {

    public enum Status {
        CREATED,
        DUPLICATE
    }
}
