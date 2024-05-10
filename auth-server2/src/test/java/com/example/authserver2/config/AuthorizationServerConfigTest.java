package com.example.authserver2.config;
import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.mockito.Mock;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import java.security.NoSuchAlgorithmException;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;
import java.time.Duration;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@TestPropertySource(locations = "classpath:application.yml")
class AuthorizationServerConfigTest {

    @Autowired
    RegisteredClientConfigProperties clientConfigProperties;

    @Autowired
    private AuthorizationServerConfig authorizationServerConfig;

    @Autowired
    private WebApplicationContext context;


    @Mock
    private RegisteredClientRepository mockRegisteredClientRepository;


    @Test
    void testUnauthorizedEndpoint() throws Exception {
        MockMvc mockMvc = MockMvcBuilders.webAppContextSetup(context)
                .apply(SecurityMockMvcConfigurers.springSecurity())
                .build();

        mockMvc.perform(get("/**"))
                .andExpect(status().isUnauthorized());
    }


    @Test
    void testRegisteredClientRepository() {

        RegisteredClientRepository repository = authorizationServerConfig.registeredClientRepository();
        assertThat(repository).isNotNull();
        // Test that the repository contains expected client with specific configurations
        RegisteredClient client = repository.findByClientId(clientConfigProperties.getClientId());
        assertThat(client).isNotNull();
        assertThat(client.getClientId()).isEqualTo(clientConfigProperties.getClientId());
        assertThat(client.getTokenSettings().getAccessTokenTimeToLive()).isEqualTo(Duration.ofMinutes(60));
    }

    @Test
    void testJwkSource() throws NoSuchAlgorithmException {
        JWKSource<SecurityContext> jwkSource = authorizationServerConfig.jwkSource();
        assertThat(jwkSource).isNotNull();
        // Further assertions could be made to validate the JWKSource implementation
    }

    @Test
    void testAuthorizationServerSettings() {
        AuthorizationServerSettings settings = authorizationServerConfig.authorizationServerSettings();
        assertThat(settings).isNotNull();
        assertThat(settings.getIssuer()).isEqualTo(clientConfigProperties.getJwtIssuerUri());
    }

}
