package kr.sproutfx.common.sproutfxcommonsecurityspringbootstarter.configuration.authorization.property;

import org.springframework.boot.context.properties.ConfigurationProperties;

import lombok.Getter;
import lombok.Setter;

@ConfigurationProperties(prefix = "sproutfx.security.web")
@Getter @Setter
public class WebProperties {
    private PatternMatcher ignore;
}