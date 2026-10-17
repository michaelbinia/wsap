package com.security.wsa;

import com.security.wsa.config.MiniWsaProperties;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;

@SpringBootApplication
@EnableConfigurationProperties(MiniWsaProperties.class)
public class MiniWsaApplication {

    public static void main(String[] args) {
        SpringApplication.run(MiniWsaApplication.class, args);
    }
}
