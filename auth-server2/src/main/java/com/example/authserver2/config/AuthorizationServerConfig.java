package com.example.authserver2.config;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.security.web.SecurityFilterChain;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Duration;
import java.util.UUID;

@Configuration
public class AuthorizationServerConfig {

    private final RegisteredClientConfigProperties clientConfigProperties;

    @Autowired
    public AuthorizationServerConfig(RegisteredClientConfigProperties clientConfigProperties) {
        this.clientConfigProperties = clientConfigProperties;
    }

    // Security configuration for OAuth2 Authorization Server
    @Bean
    @Order(Ordered.HIGHEST_PRECEDENCE)
    public SecurityFilterChain authServerSecurityFilterChain(HttpSecurity http) throws Exception {
        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);
        http
                .oauth2ResourceServer(oauth2 -> oauth2.jwt(Customizer.withDefaults()));
        return http.build();
    }

    // Default security configuration for the application (e.g., resource server)
    @Bean
    @Order(2)
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests(authorize ->
                        authorize
                                .anyRequest().authenticated()  // Require authentication for all endpoints
                )
                .formLogin(Customizer.withDefaults())  // Form-based login
                .oauth2ResourceServer(oauth2 -> oauth2.jwt(Customizer.withDefaults()));  // JWT-based resource server
        return http.build();
    }




        @Bean
    public RegisteredClientRepository registeredClientRepository() {
        TokenSettings tokenSettings = TokenSettings.builder()
                .accessTokenTimeToLive(Duration.ofMinutes(clientConfigProperties.getAccessTokenLifetime()))  // Access token lifespan
                .refreshTokenTimeToLive(Duration.ofDays(clientConfigProperties.getRefreshTokenLifetime()))  // Refresh token lifespan
                .build();

        RegisteredClient registeredClient = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId(clientConfigProperties.getClientId())
                .clientSecret("{noop}"+clientConfigProperties.getClientSecret())  // It's recommended to hash client secrets in production
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)  // Basic authentication for clients
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)  // Client credentials grant type
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)  // Support for refresh tokens
                .tokenSettings(tokenSettings)
                .build();
        return new InMemoryRegisteredClientRepository(registeredClient);
    }

    //     Repository for registered clients
//    @Bean
//    public RegisteredClientRepository registeredClientRepository() {
//        TokenSettings tokenSettings = TokenSettings.builder()
//                .accessTokenTimeToLive(java.time.Duration.ofMinutes(60))  // Access token lifespan
//                .refreshTokenTimeToLive(java.time.Duration.ofDays(30))  // Refresh token lifespan
//                .build();
//
//        RegisteredClient registeredClient = RegisteredClient.withId(UUID.randomUUID().toString())
//                .clientId("oauth-client")
//                .clientSecret("{noop}oauth-secret")  // It's recommended to hash client secrets in production
//                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)  // Basic authentication for clients
//                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)  // Client credentials grant type
//                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)  // Support for refresh tokens
//                .tokenSettings(tokenSettings)
//                .build();
//        return new InMemoryRegisteredClientRepository(registeredClient);
//    }



    // JWK source for generating RSA keys
    @Bean
    public JWKSource<SecurityContext> jwkSource() throws NoSuchAlgorithmException {
        RSAKey rsaKey = generateRsa();
        JWKSet jwkSet = new JWKSet(rsaKey);
        return (jwkSelector, securityContext) -> jwkSelector.select(jwkSet);
    }

    // Method to generate RSA keys
    private static RSAKey generateRsa() throws NoSuchAlgorithmException {
        KeyPair keyPair = generateRsaKey();
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
        return new RSAKey.Builder(publicKey)
                .privateKey(privateKey)
                .keyID(UUID.randomUUID().toString())
                .build();
    }

    // Helper method for generating RSA key pair
    private static KeyPair generateRsaKey() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);  // RSA key size
        return keyPairGenerator.generateKeyPair();
    }

    // JWT decoder for decoding tokens
    @Bean
    public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
    }

//     Basic authorization server settings
    @Bean
    public AuthorizationServerSettings authorizationServerSettings() {
        return AuthorizationServerSettings.builder()
                .issuer(clientConfigProperties.getJwtIssuerUri())  // Set issuer to distinguish tokens
                .authorizationEndpoint("/oauth2/authorize")  // Default authorization endpoint
                .tokenEndpoint("/oauth2/token")  // Default token endpoint
                .build();
    }

}
