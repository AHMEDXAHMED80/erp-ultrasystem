package com.ultrasystem.erp.auth.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@Data
@Configuration
@ConfigurationProperties(prefix = "keycloak")
public class KeycloakProperties {

    private String authServerUrl;   // http://localhost:8180
    private String realm;           // erp-ultrasystem
    private String clientId;        // erp-client
    private String clientSecret;    // 06c9xZfObjTSfzR5eoyrtAZDOZdXzlFC
    private String adminUsername;   // admin
    private String adminPassword;   // admin
}
