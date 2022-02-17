package kr.sproutfx.common.sproutfxcommonsecurityspringbootstarter.configuration.jwt;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;

import kr.sproutfx.common.sproutfxcommonsecurityspringbootstarter.configuration.JwtConfiguration;
import kr.sproutfx.common.sproutfxcommonsecurityspringbootstarter.configuration.jwt.component.JwtProvider;

@SpringBootTest
public class AuthorizationPropertyTest {
    private final ApplicationContextRunner contextRunner = new ApplicationContextRunner();
    private String authorizationPropertyPrefix = "sproutfx.security.authorization";

    @Test
    public void bindingTest() {
        contextRunner
            .withPropertyValues(authorizationPropertyPrefix + ".header=Authorization")
            .withPropertyValues(authorizationPropertyPrefix + ".type=Bearer")
            .withPropertyValues(authorizationPropertyPrefix + ".provider-code=test-provider-code")
            .withPropertyValues(authorizationPropertyPrefix + ".client-code=test-client-code")
            .withPropertyValues(authorizationPropertyPrefix + ".access-token-secret=test-access-token-secret")
            .withUserConfiguration(JwtConfiguration.class)
            .run(context -> {
                var jwtProvider = context.getBean(JwtProvider.class);

                assertNotNull(jwtProvider);
                assertEquals(jwtProvider.getAuthorizationHeader(), "Authorization");
                assertEquals(jwtProvider.getAuthorizationType(), "Bearer");
            });
    }
}
