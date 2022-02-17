package kr.sproutfx.common.sproutfxcommonsecurityspringbootstarter.configuration.authorization.property;

import org.springframework.boot.context.properties.ConfigurationProperties;

import lombok.Getter;
import lombok.Setter;

@ConfigurationProperties(prefix = "sproutfx.security.http")
@Getter @Setter
public class HttpProperties {
    private AuthMatcher authorizeRequests;

    @Getter @Setter
    public static class AuthMatcher {
        private PatternMatcher permitAll;

        private PatternMatcher permitGet;
        private PatternMatcher permitPost;
        private PatternMatcher permitPut;
        private PatternMatcher permitDelete;
    }
}