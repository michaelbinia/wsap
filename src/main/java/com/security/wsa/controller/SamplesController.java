package com.security.wsa.controller;

import com.security.wsa.model.SamplesResponse;
import com.security.wsa.model.enums.Action;
import com.security.wsa.model.enums.AttackCategory;
import com.security.wsa.service.SamplesService;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;

@RestController
@Validated
@RequestMapping("/v1/events")
public class SamplesController {

    private final SamplesService samplesService;

    public SamplesController(SamplesService samplesService) {
        this.samplesService = samplesService;
    }

    @GetMapping("/samples")
    public SamplesResponse samples(
            @RequestParam(required = false) Integer configId,
            @RequestParam(required = false) Instant from,
            @RequestParam(required = false) Instant to,
            @RequestParam(required = false) AttackCategory category,
            @RequestParam(required = false) Action action,
            @RequestParam(defaultValue = "20") @Min(1) @Max(100) int limit,
            @RequestParam(defaultValue = "0") @Min(0) int offset) {
        return samplesService.search(configId, from, to, category, action, limit, offset);
    }
}
