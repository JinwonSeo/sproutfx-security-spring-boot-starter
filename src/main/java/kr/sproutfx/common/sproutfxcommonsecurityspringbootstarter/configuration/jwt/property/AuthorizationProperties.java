package kr.sproutfx.common.sproutfxcommonsecurityspringbootstarter.configuration.jwt.property;

import org.springframework.boot.context.properties.ConfigurationProperties;

import lombok.Getter;
import lombok.Setter;

@ConfigurationProperties(prefix = "sproutfx.security.authorization")
@Getter @Setter
public class AuthorizationProperties {
    private String header;
    private String type;
    private String providerCode;
    private String clientCode;
    private String accessTokenSecret;
}
