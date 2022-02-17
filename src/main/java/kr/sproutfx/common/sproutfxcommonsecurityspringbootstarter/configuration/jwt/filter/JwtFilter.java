package kr.sproutfx.common.sproutfxcommonsecurityspringbootstarter.configuration.jwt.filter;

import java.io.IOException;
import java.util.ArrayList;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;

import org.apache.commons.lang3.StringUtils;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.web.filter.GenericFilterBean;

import kr.sproutfx.common.sproutfxcommonsecurityspringbootstarter.configuration.jwt.component.JwtProvider;

public class JwtFilter extends GenericFilterBean {
    private JwtProvider jwtProvider;

    public JwtFilter(JwtProvider jwtProvider) {
        this.jwtProvider = jwtProvider;
    }

    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {
        String accessToken = resolveTokenFromHttpServletRequest((HttpServletRequest) servletRequest);

        try {
            if (this.jwtProvider.validateAccessToken(accessToken)) {
                SecurityContextHolder
                    .getContext()
                    .setAuthentication(this.createAuthenticationByAccessToken(accessToken));
            }

            filterChain.doFilter(servletRequest, servletResponse);
        } finally {
            SecurityContextHolder.clearContext();
        }
    }

    private Authentication createAuthenticationByAccessToken(String accessToken) {
        return new UsernamePasswordAuthenticationToken(new User(this.jwtProvider.extractSubjectFromAccessToken(accessToken), StringUtils.EMPTY , new ArrayList<>()), accessToken, null);
    }

    private String resolveTokenFromHttpServletRequest(HttpServletRequest httpServletRequest) {
        return this.jwtProvider.removePrefixOfToken(httpServletRequest.getHeader(this.jwtProvider.getAuthorizationHeader()));
    }

}
