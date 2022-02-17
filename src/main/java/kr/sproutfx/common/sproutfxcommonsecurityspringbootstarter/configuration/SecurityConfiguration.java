package kr.sproutfx.common.sproutfxcommonsecurityspringbootstarter.configuration;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.AutoConfigureAfter;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsUtils;

import kr.sproutfx.common.sproutfxcommonsecurityspringbootstarter.configuration.authorization.filter.HttpFirewallFilter;
import kr.sproutfx.common.sproutfxcommonsecurityspringbootstarter.configuration.authorization.property.HttpProperties;
import kr.sproutfx.common.sproutfxcommonsecurityspringbootstarter.configuration.authorization.property.PatternMatcher;
import kr.sproutfx.common.sproutfxcommonsecurityspringbootstarter.configuration.authorization.property.WebProperties;
import kr.sproutfx.common.sproutfxcommonsecurityspringbootstarter.configuration.jwt.component.JwtProvider;
import kr.sproutfx.common.sproutfxcommonsecurityspringbootstarter.configuration.jwt.filter.JwtFilter;
import kr.sproutfx.common.sproutfxcommonsecurityspringbootstarter.utility.PatternMatchingFunction;

@AutoConfigureAfter({ WebSecurityConfigurerAdapter.class, JwtConfiguration.class })
@Configuration
@EnableConfigurationProperties({ WebProperties.class, HttpProperties.class })
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {
    private final Logger logger = LoggerFactory.getLogger(SecurityConfiguration.class);

    private JwtProvider jwtProvider;
    private WebProperties webProperties;
    private HttpProperties httpProperties;

    @Autowired
    public SecurityConfiguration(JwtProvider jwtProvider, WebProperties webProperties, HttpProperties httpProperties) {
        super();

        this.jwtProvider = jwtProvider;
        this.webProperties = webProperties;
        this.httpProperties = httpProperties;
    }

    @Override
    public void configure(WebSecurity webSecurity) throws Exception {
        webSecurity
            .httpFirewall(new HttpFirewallFilter());

        if (this.webProperties != null) {
            var ignorePatterns = this.webProperties.getIgnore();

            if (ignorePatterns != null) {
                for (String pattern : ignorePatterns.getPatterns()) {
                    webSecurity.ignoring()
                        .antMatchers(pattern);
                }
            }
        }
    }

    @Override
    public void configure(HttpSecurity httpSecurity) throws Exception {
        if (this.httpProperties != null) {
            var authorizeRequests = this.httpProperties.getAuthorizeRequests();

            if (authorizeRequests != null) {
                configPattern(authorizeRequests.getPermitAll(), (pattern) -> {
                    httpSecurity.authorizeRequests()
                        .antMatchers(pattern)
                        .permitAll();
                });

                configPattern(authorizeRequests.getPermitGet(), (pattern) -> {
                    httpSecurity.authorizeRequests()
                        .antMatchers(HttpMethod.GET, pattern)
                        .permitAll();
                });
                
                configPattern(authorizeRequests.getPermitPost(), (pattern) -> {
                    httpSecurity.authorizeRequests()
                        .antMatchers(HttpMethod.POST, pattern)
                        .permitAll();
                });

                configPattern(authorizeRequests.getPermitPut(), (pattern) -> {
                    httpSecurity.authorizeRequests()
                        .antMatchers(HttpMethod.PUT, pattern)
                        .permitAll();
                });

                configPattern(authorizeRequests.getPermitDelete(), (pattern) -> {
                    httpSecurity.authorizeRequests()
                        .antMatchers(HttpMethod.DELETE, pattern)
                        .permitAll();
                });
            }
        }

        httpSecurity.addFilterBefore(new JwtFilter(this.jwtProvider), UsernamePasswordAuthenticationFilter.class)
            .csrf().disable().cors().and()
            .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS).and()
            .authorizeRequests().requestMatchers(CorsUtils::isPreFlightRequest).permitAll()
            .anyRequest().authenticated();
    }

    private void configPattern(PatternMatcher patternMatcher, PatternMatchingFunction patternMatchingFunction) {
        if (patternMatcher != null) {
            for (String pattern : patternMatcher.getPatterns()) {
                try {
                    patternMatchingFunction.matchPattern(pattern);
                }

                catch (Exception e) {
                    logger.warn("Pattern matching failed. {} \r\n {}", pattern, e.getMessage());
                }
            }
        }
    }
}
