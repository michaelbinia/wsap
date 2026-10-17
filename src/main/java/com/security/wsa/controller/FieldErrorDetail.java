package com.security.wsa.controller;

public record FieldErrorDetail(
        Integer index,
        String field,
        String message
) {
}
