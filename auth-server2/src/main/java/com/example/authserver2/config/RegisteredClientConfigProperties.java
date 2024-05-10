package com.example.authserver2.config;

import lombok.Getter;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Getter
@Component
public class RegisteredClientConfigProperties {

    @Value("${spring.security.oauth2.client.id}")
    private String clientId;

    @Value("${spring.security.oauth2.client.secret}")
    private String clientSecret;

    @Value("${spring.security.oauth2.client.token.access-token-lifetime}")
    private int accessTokenLifetime;

    @Value("${spring.security.oauth2.client.token.refresh-token-lifetime}")
    private int refreshTokenLifetime;

    @Value("${spring.security.oauth2.resourceserver.jwt.issuer-uri}")
    private String jwtIssuerUri;

}
