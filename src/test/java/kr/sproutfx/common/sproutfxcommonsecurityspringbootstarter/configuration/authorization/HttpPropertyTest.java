package kr.sproutfx.common.sproutfxcommonsecurityspringbootstarter.configuration.authorization;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.test.context.ActiveProfiles;

import kr.sproutfx.common.sproutfxcommonsecurityspringbootstarter.configuration.JwtConfiguration;
import kr.sproutfx.common.sproutfxcommonsecurityspringbootstarter.configuration.SecurityConfiguration;
import kr.sproutfx.common.sproutfxcommonsecurityspringbootstarter.configuration.authorization.property.HttpProperties;

@SpringBootTest
@ActiveProfiles("test")
public class HttpPropertyTest {
    private final ApplicationContextRunner contextRunner = new ApplicationContextRunner();
    private String httpPropertyPrefix = "sproutfx.security.http";

    @Test
    public void bindingTest() {
        contextRunner
            .withPropertyValues(httpPropertyPrefix + ".authorize-requests.permit-all.patterns[0]=/test/http")
            .withUserConfiguration(AuthenticationConfiguration.class, JwtConfiguration.class, SecurityConfiguration.class)
            .run(context -> {
                var httpProperty = context.getBean(HttpProperties.class);

                assertNotNull(httpProperty);
                assertNotNull(httpProperty.getAuthorizeRequests());
                assertNotNull(httpProperty.getAuthorizeRequests().getPermitAll());
                assertNull(httpProperty.getAuthorizeRequests().getPermitGet());
            });
    }
}