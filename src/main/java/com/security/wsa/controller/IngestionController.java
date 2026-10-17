package com.security.wsa.controller;

import com.security.wsa.model.IngestResult;
import com.security.wsa.model.SecurityEventDto;
import com.security.wsa.service.IngestionService;
import jakarta.validation.ConstraintViolation;
import jakarta.validation.Validator;
import jakarta.validation.constraints.Size;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

@RestController
@RequestMapping("/v1/events")
@Validated
public class IngestionController {

    private static final int MAX_BATCH_SIZE = 10_000;

    private final IngestionService ingestionService;
    private final Validator validator;

    public IngestionController(IngestionService ingestionService, Validator validator) {
        this.ingestionService = ingestionService;
        this.validator = validator;
    }

    @PostMapping("/ingest")
    public ResponseEntity<List<IngestResult>> ingest(
            @RequestBody
            @Size(min = 1, max = MAX_BATCH_SIZE,
                    message = "Batch must contain between 1 and " + MAX_BATCH_SIZE + " events")
            List<SecurityEventDto> events) {

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

        List<IngestResult> results = ingestionService.ingestBatch(events);
        boolean anyCreated = results.stream()
                .anyMatch(r -> r.status() == IngestResult.Status.CREATED);
        HttpStatus status = anyCreated ? HttpStatus.CREATED : HttpStatus.OK;
        return ResponseEntity.status(status).body(results);
    }
}
