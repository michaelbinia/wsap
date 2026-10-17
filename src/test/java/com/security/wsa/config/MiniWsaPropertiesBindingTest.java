package com.security.wsa.config;

import com.security.wsa.model.enums.Action;
import com.security.wsa.model.enums.Severity;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest
@Testcontainers
class MiniWsaPropertiesBindingTest {

    @Container
    static final PostgreSQLContainer<?> PG = new PostgreSQLContainer<>("postgres:16");

    @DynamicPropertySource
    static void props(DynamicPropertyRegistry r) {
        r.add("spring.datasource.url", PG::getJdbcUrl);
        r.add("spring.datasource.username", PG::getUsername);
        r.add("spring.datasource.password", PG::getPassword);
    }

    @Autowired
    MiniWsaProperties properties;

    @Test
    void defaultsFromApplicationYmlMatchPdf() {
        assertThat(properties.scoring().maxScore()).isEqualTo(100);
        assertThat(properties.scoring().severity())
                .containsEntry(Severity.CRITICAL, 40)
                .containsEntry(Severity.HIGH, 30)
                .containsEntry(Severity.MEDIUM, 20)
                .containsEntry(Severity.LOW, 10);
        assertThat(properties.scoring().action())
                .containsEntry(Action.DENY, 20)
                .containsEntry(Action.ALERT, 10)
                .containsEntry(Action.MONITOR, 0);
        assertThat(properties.scoring().sensitivePath().bonus()).isEqualTo(15);
        assertThat(properties.scoring().sensitivePath().markers()).containsExactly("/admin", "/login");
        assertThat(properties.scoring().repeatOffender().window()).isEqualTo(Duration.ofMinutes(10));
        assertThat(properties.scoring().repeatOffender().threshold()).isEqualTo(5);
        assertThat(properties.scoring().repeatOffender().bonus()).isEqualTo(15);
        assertThat(properties.stats().topN()).isEqualTo(10);
        assertThat(properties.samples()).isEqualTo(new MiniWsaProperties.Samples(20, 100));
    }
}
