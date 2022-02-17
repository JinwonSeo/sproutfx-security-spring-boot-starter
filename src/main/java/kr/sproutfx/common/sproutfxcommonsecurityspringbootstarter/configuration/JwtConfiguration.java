package kr.sproutfx.common.sproutfxcommonsecurityspringbootstarter.configuration;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import kr.sproutfx.common.sproutfxcommonsecurityspringbootstarter.configuration.jwt.component.JwtProvider;
import kr.sproutfx.common.sproutfxcommonsecurityspringbootstarter.configuration.jwt.property.AuthorizationProperties;

@Configuration
@EnableConfigurationProperties({ AuthorizationProperties.class })
public class JwtConfiguration {

    private AuthorizationProperties authorizationProperties;
    
    @Autowired
    public JwtConfiguration (AuthorizationProperties authorizationProperties) {
        this.authorizationProperties = authorizationProperties;
    }

    @Bean
    public JwtProvider jwtProvider() {
        return new JwtProvider(this.authorizationProperties);
    }
}
