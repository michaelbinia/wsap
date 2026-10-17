package com.security.wsa.generator;

import com.security.wsa.model.SecurityEventDto;
import com.security.wsa.model.enums.AttackCategory;
import com.security.wsa.model.enums.Severity;
import jakarta.validation.ConstraintViolation;
import jakarta.validation.Validation;
import jakarta.validation.Validator;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Random;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

class RandomEventFactoryTest {

    private static final List<String> ALLOWED_METHODS = List.of("GET", "POST", "PUT");
    private static final List<Integer> ALLOWED_STATUS = List.of(200, 400, 401, 403, 429, 500);
    private static final List<Integer> ALLOWED_CONFIG_IDS = List.of(14227, 14228, 14229);

    private static final Validator VALIDATOR = Validation.buildDefaultValidatorFactory().getValidator();

    @Test
    void producesDtosThatPassJakartaValidation() {
        RandomEventFactory factory = new RandomEventFactory(new Random(42L));

        for (int i = 0; i < 100; i++) {
            SecurityEventDto dto = factory.next(600);
            Set<ConstraintViolation<SecurityEventDto>> violations = VALIDATOR.validate(dto);
            assertThat(violations)
                    .withFailMessage("iteration %d violations: %s", i, violations)
                    .isEmpty();
        }
    }

    @Test
    void producesFieldsFromTheConfiguredPools() {
        RandomEventFactory factory = new RandomEventFactory(new Random(1L));

        for (int i = 0; i < 50; i++) {
            SecurityEventDto dto = factory.next(600);
            assertThat(dto.method()).isIn(ALLOWED_METHODS);
            assertThat(dto.statusCode()).isIn(ALLOWED_STATUS);
            assertThat(dto.configId()).isIn(ALLOWED_CONFIG_IDS);
            assertThat(RandomEventFactory.ipPool()).contains(dto.clientIp());
            assertThat(RandomEventFactory.paths()).contains(dto.path());
            assertThat(dto.policyId()).matches("pol_web[1-3]");
        }
    }

    @Test
    void severityMatchesCategoryForEveryGeneratedEvent() {
        RandomEventFactory factory = new RandomEventFactory(new Random(7L));

        for (int i = 0; i < 50; i++) {
            SecurityEventDto dto = factory.next(600);
            AttackCategory category = dto.rule().category();
            Severity severity = dto.rule().severity();
            switch (category) {
                case INJECTION, DATA_LEAKAGE -> assertThat(severity).isEqualTo(Severity.CRITICAL);
                case XSS, DOS -> assertThat(severity).isEqualTo(Severity.HIGH);
                case PROTOCOL_VIOLATION -> assertThat(severity).isEqualTo(Severity.MEDIUM);
                case BOT, RATE_LIMIT -> assertThat(severity).isEqualTo(Severity.LOW);
            }
        }
    }

    @Test
    void sameSeedProducesSameSequenceOfEventIds() {
        RandomEventFactory a = new RandomEventFactory(new Random(123L));
        RandomEventFactory b = new RandomEventFactory(new Random(123L));

        for (int i = 0; i < 10; i++) {
            assertThat(a.next(600).eventId()).isEqualTo(b.next(600).eventId());
        }
    }
}
