package com.security.wsa.controller;

import com.security.wsa.service.IngestionService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import java.util.List;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest(controllers = IngestionController.class)
class GlobalExceptionHandlerTest {

    @Autowired
    MockMvc mockMvc;

    @MockitoBean
    IngestionService ingestionService;

    @Test
    void returns400WithFieldErrorsForBeanValidationFailures() throws Exception {
        String body = """
                [
                  {
                    "eventId": "evt-1",
                    "timestamp": "2026-05-20T14:32:10Z",
                    "configId": 14227,
                    "clientIp": "203.0.113.42",
                    "hostname": "www.example.com",
                    "path": "/api/v1/login",
                    "method": "POST",
                    "statusCode": 403,
                    "rule": {
                      "id": "950001",
                      "name": "SQL_INJECTION",
                      "severity": null,
                      "category": "INJECTION"
                    },
                    "action": "DENY"
                  }
                ]
                """;

        mockMvc.perform(post("/v1/events/ingest").contentType("application/json").content(body))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.status").value(400))
                .andExpect(jsonPath("$.error").value("Validation failed"))
                .andExpect(jsonPath("$.fieldErrors[0].index").value(0))
                .andExpect(jsonPath("$.fieldErrors[0].field").value("rule.severity"))
                .andExpect(jsonPath("$.fieldErrors[0].message").value("must not be null"));
    }

    @Test
    void batchValidationCarriesPerElementIndex() throws Exception {
        String body = """
                [
                  {
                    "eventId": "evt-1",
                    "timestamp": "2026-05-20T14:32:10Z",
                    "configId": 14227,
                    "clientIp": "203.0.113.42",
                    "hostname": "www.example.com",
                    "path": "/api/v1/login",
                    "method": "POST",
                    "statusCode": 403,
                    "rule": {
                      "id": "950001",
                      "name": "SQL_INJECTION",
                      "severity": "CRITICAL",
                      "category": "INJECTION"
                    },
                    "action": "DENY"
                  },
                  {
                    "eventId": "evt-2",
                    "timestamp": "2026-05-20T14:32:11Z",
                    "configId": 14227,
                    "clientIp": "",
                    "hostname": "www.example.com",
                    "path": "/api/v1/login",
                    "method": "POST",
                    "statusCode": 403,
                    "rule": {
                      "id": "950001",
                      "name": "SQL_INJECTION",
                      "severity": "CRITICAL",
                      "category": "INJECTION"
                    },
                    "action": "DENY"
                  }
                ]
                """;

        mockMvc.perform(post("/v1/events/ingest").contentType("application/json").content(body))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.fieldErrors[0].index").value(1))
                .andExpect(jsonPath("$.fieldErrors[0].field").value("clientIp"));
    }

    @Test
    void returns400WhenJsonIsMalformed() throws Exception {
        mockMvc.perform(post("/v1/events/ingest").contentType("application/json").content("not json"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("Malformed request body"));
    }

    @Test
    void returns400OnUnknownEnumValue() throws Exception {
        String body = """
                [{
                  "eventId": "evt-1",
                  "timestamp": "2026-05-20T14:32:10Z",
                  "configId": 14227,
                  "clientIp": "203.0.113.42",
                  "hostname": "www.example.com",
                  "path": "/api/v1/login",
                  "method": "POST",
                  "statusCode": 403,
                  "rule": {
                    "id": "950001", "name": "SQL_INJECTION",
                    "severity": "CRITICAL", "category": "BOGUS"
                  },
                  "action": "DENY"
                }]
                """;

        mockMvc.perform(post("/v1/events/ingest").contentType("application/json").content(body))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("Malformed request body"));
    }

    @Test
    void returns400OnEmptyBatch() throws Exception {
        mockMvc.perform(post("/v1/events/ingest").contentType("application/json").content("[]"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.status").value(400))
                .andExpect(jsonPath("$.message").value("At least one event required"));
    }

    @Test
    void returns409OnDataIntegrityViolation() throws Exception {
        when(ingestionService.ingestBatch(any()))
                .thenThrow(new DataIntegrityViolationException("duplicate key"));

        String body = """
                [{
                  "eventId": "evt-1",
                  "timestamp": "2026-05-20T14:32:10Z",
                  "configId": 14227,
                  "clientIp": "203.0.113.42",
                  "hostname": "www.example.com",
                  "path": "/api/v1/login",
                  "method": "POST",
                  "statusCode": 403,
                  "rule": {
                    "id": "950001", "name": "SQL_INJECTION",
                    "severity": "CRITICAL", "category": "INJECTION"
                  },
                  "action": "DENY"
                }]
                """;

        mockMvc.perform(post("/v1/events/ingest").contentType("application/json").content(body))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.status").value(409))
                .andExpect(jsonPath("$.error").value("Conflict"));
    }

    @Test
    void returns500OnUnexpectedExceptionWithoutLeakingStackTrace() throws Exception {
        when(ingestionService.ingestBatch(any())).thenThrow(new RuntimeException("boom internals"));

        String body = """
                [{
                  "eventId": "evt-1",
                  "timestamp": "2026-05-20T14:32:10Z",
                  "configId": 14227,
                  "clientIp": "203.0.113.42",
                  "hostname": "www.example.com",
                  "path": "/api/v1/login",
                  "method": "POST",
                  "statusCode": 403,
                  "rule": {
                    "id": "950001", "name": "SQL_INJECTION",
                    "severity": "CRITICAL", "category": "INJECTION"
                  },
                  "action": "DENY"
                }]
                """;

        mockMvc.perform(post("/v1/events/ingest").contentType("application/json").content(body))
                .andExpect(status().isInternalServerError())
                .andExpect(jsonPath("$.status").value(500))
                .andExpect(jsonPath("$.message").value("An unexpected error occurred"));
    }
}
