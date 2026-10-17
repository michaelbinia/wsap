package com.security.wsa.controller;

import java.util.List;

public class BatchValidationException extends RuntimeException {

    private final List<FieldErrorDetail> fieldErrors;

    public BatchValidationException(List<FieldErrorDetail> fieldErrors) {
        super("Validation failed");
        this.fieldErrors = List.copyOf(fieldErrors);
    }

    public List<FieldErrorDetail> getFieldErrors() {
        return fieldErrors;
    }
}
