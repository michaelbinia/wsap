package com.security.wsa.controller;

import com.security.wsa.model.SecurityEvent;
import com.security.wsa.model.SecurityEventDto;
import com.security.wsa.service.IngestionService;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
@RequestMapping("/v1/events")
public class IngestionController {

    private final IngestionService ingestionService;

    public IngestionController(IngestionService ingestionService) {
        this.ingestionService = ingestionService;
    }

    @PostMapping("/ingest")
    public ResponseEntity<List<SecurityEvent>> ingest(
            @RequestBody @Valid List<@Valid SecurityEventDto> events) {
        if (events == null || events.isEmpty()) {
            throw new IllegalArgumentException("At least one event required");
        }
        return ResponseEntity.status(HttpStatus.CREATED)
                .body(ingestionService.ingestBatch(events));
    }
}
