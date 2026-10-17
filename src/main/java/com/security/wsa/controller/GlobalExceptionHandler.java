package com.security.wsa.controller;

import jakarta.validation.ConstraintViolationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.method.annotation.HandlerMethodValidationException;
import org.springframework.web.method.annotation.MethodArgumentTypeMismatchException;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@RestControllerAdvice
public class GlobalExceptionHandler {

    private static final Logger log = LoggerFactory.getLogger(GlobalExceptionHandler.class);

    private static final Pattern BATCH_PATH = Pattern.compile("^(?:\\w+)?\\[(\\d+)\\]\\.(.+)$");

    @ExceptionHandler(BatchValidationException.class)
    public ResponseEntity<ErrorResponse> handleBatchValidation(BatchValidationException ex) {
        return ResponseEntity.badRequest()
                .body(ErrorResponse.ofValidation(HttpStatus.BAD_REQUEST.value(), "Validation failed", ex.getFieldErrors()));
    }

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ErrorResponse> handleBeanValidation(MethodArgumentNotValidException ex) {
        List<FieldErrorDetail> details = ex.getBindingResult().getFieldErrors().stream()
                .map(GlobalExceptionHandler::toFieldErrorDetail)
                .toList();
        return ResponseEntity.badRequest()
                .body(ErrorResponse.ofValidation(HttpStatus.BAD_REQUEST.value(), "Validation failed", details));
    }

    @ExceptionHandler(HandlerMethodValidationException.class)
    public ResponseEntity<ErrorResponse> handleHandlerMethodValidation(HandlerMethodValidationException ex) {
        List<FieldErrorDetail> details = new ArrayList<>();
        ex.getAllValidationResults().forEach(result -> result.getResolvableErrors().forEach(error -> {
            String rawPath = error.getCodes() != null && error.getCodes().length > 0
                    ? error.getCodes()[0]
                    : "";
            details.add(parsePath(rawPath, error.getDefaultMessage()));
        }));
        return ResponseEntity.badRequest()
                .body(ErrorResponse.ofValidation(HttpStatus.BAD_REQUEST.value(), "Validation failed", details));
    }

    @ExceptionHandler(ConstraintViolationException.class)
    public ResponseEntity<ErrorResponse> handleConstraintViolation(ConstraintViolationException ex) {
        return ResponseEntity.badRequest()
                .body(ErrorResponse.of(HttpStatus.BAD_REQUEST.value(), "Validation failed", ex.getMessage()));
    }

    @ExceptionHandler(MethodArgumentTypeMismatchException.class)
    public ResponseEntity<ErrorResponse> handleTypeMismatch(MethodArgumentTypeMismatchException ex) {
        String required = ex.getRequiredType() != null ? ex.getRequiredType().getSimpleName() : "unknown";
        String message = "Parameter '" + ex.getName() + "' could not be converted to " + required
                + " (value: '" + ex.getValue() + "')";
        return ResponseEntity.badRequest()
                .body(ErrorResponse.of(HttpStatus.BAD_REQUEST.value(), "Invalid request parameter", message));
    }

    @ExceptionHandler(HttpMessageNotReadableException.class)
    public ResponseEntity<ErrorResponse> handleUnreadable(HttpMessageNotReadableException ex) {
        return ResponseEntity.badRequest()
                .body(ErrorResponse.of(HttpStatus.BAD_REQUEST.value(), "Malformed request body", ex.getMostSpecificCause().getMessage()));
    }

    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<ErrorResponse> handleIllegalArgument(IllegalArgumentException ex) {
        return ResponseEntity.badRequest()
                .body(ErrorResponse.of(HttpStatus.BAD_REQUEST.value(), "Bad request", ex.getMessage()));
    }

    @ExceptionHandler(DataIntegrityViolationException.class)
    public ResponseEntity<ErrorResponse> handleConflict(DataIntegrityViolationException ex) {
        log.warn("Database integrity violation", ex);
        return ResponseEntity.status(HttpStatus.CONFLICT)
                .body(ErrorResponse.of(HttpStatus.CONFLICT.value(), "Conflict", "A database constraint was violated"));
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ErrorResponse> handleUnexpected(Exception ex) {
        log.error("Unhandled exception", ex);
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(ErrorResponse.of(HttpStatus.INTERNAL_SERVER_ERROR.value(),
                        "Internal Server Error", "An unexpected error occurred"));
    }

    private static FieldErrorDetail toFieldErrorDetail(FieldError fe) {
        return parsePath(fe.getField(), fe.getDefaultMessage());
    }

    private static FieldErrorDetail parsePath(String rawPath, String message) {
        if (rawPath == null || rawPath.isEmpty()) {
            return new FieldErrorDetail(null, "", message);
        }
        Matcher m = BATCH_PATH.matcher(rawPath);
        if (m.matches()) {
            return new FieldErrorDetail(Integer.parseInt(m.group(1)), m.group(2), message);
        }
        return new FieldErrorDetail(null, rawPath, message);
    }
}
