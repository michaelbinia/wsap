package com.security.wsa.controller;

import com.fasterxml.jackson.annotation.JsonInclude;

import java.time.Instant;
import java.util.List;

@JsonInclude(JsonInclude.Include.NON_NULL)
public record ErrorResponse(
        String timestamp,
        int status,
        String error,
        String message,
        List<FieldErrorDetail> fieldErrors
) {
    public static ErrorResponse of(int status, String error, String message) {
        return new ErrorResponse(Instant.now().toString(), status, error, message, null);
    }

    public static ErrorResponse ofValidation(int status, String error, List<FieldErrorDetail> fieldErrors) {
        return new ErrorResponse(Instant.now().toString(), status, error, null, fieldErrors);
    }
}
