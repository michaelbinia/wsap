package com.security.wsa.controller;

import com.security.wsa.model.SecurityEvent;
import com.security.wsa.model.SecurityEventDto;
import com.security.wsa.service.IngestionService;
import jakarta.validation.ConstraintViolation;
import jakarta.validation.Validator;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

@RestController
@RequestMapping("/v1/events")
public class IngestionController {

    private final IngestionService ingestionService;
    private final Validator validator;

    public IngestionController(IngestionService ingestionService, Validator validator) {
        this.ingestionService = ingestionService;
        this.validator = validator;
    }

    @PostMapping("/ingest")
    public ResponseEntity<List<SecurityEvent>> ingest(@RequestBody List<SecurityEventDto> events) {
        if (events == null || events.isEmpty()) {
            throw new IllegalArgumentException("At least one event required");
        }

        List<FieldErrorDetail> errors = new ArrayList<>();
        for (int i = 0; i < events.size(); i++) {
            Set<ConstraintViolation<SecurityEventDto>> violations = validator.validate(events.get(i));
            for (ConstraintViolation<SecurityEventDto> v : violations) {
                errors.add(new FieldErrorDetail(i, v.getPropertyPath().toString(), v.getMessage()));
            }
        }
        if (!errors.isEmpty()) {
            throw new BatchValidationException(errors);
        }

        return ResponseEntity.status(HttpStatus.CREATED).body(ingestionService.ingestBatch(events));
    }
}
