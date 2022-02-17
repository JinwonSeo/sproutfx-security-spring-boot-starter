package kr.sproutfx.common.sproutfxcommonsecurityspringbootstarter.configuration.authorization;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.test.context.ActiveProfiles;

import kr.sproutfx.common.sproutfxcommonsecurityspringbootstarter.configuration.JwtConfiguration;
import kr.sproutfx.common.sproutfxcommonsecurityspringbootstarter.configuration.SecurityConfiguration;
import kr.sproutfx.common.sproutfxcommonsecurityspringbootstarter.configuration.authorization.property.WebProperties;

@SpringBootTest
@ActiveProfiles("test")
public class WebPropertyTest {
    private final ApplicationContextRunner contextRunner = new ApplicationContextRunner();
    private String webPropertyPrefix = "sproutfx.security.web";

    @Test
    public void bindingTest() {
        contextRunner
            .withPropertyValues(webPropertyPrefix + ".ignore.patterns[0]=/test/web")
            .withUserConfiguration(AuthenticationConfiguration.class, JwtConfiguration.class, SecurityConfiguration.class)
            .run(context -> {
                var webProperty = context.getBean(WebProperties.class);

                assertNotNull(webProperty);
                assertNotNull(webProperty.getIgnore());
                assertNotNull(webProperty.getIgnore().getPatterns());

                assertEquals(webProperty.getIgnore().getPatterns().size(), 1);
                assertEquals(webProperty.getIgnore().getPatterns().get(0), "/test/web");
            });
    }
}
