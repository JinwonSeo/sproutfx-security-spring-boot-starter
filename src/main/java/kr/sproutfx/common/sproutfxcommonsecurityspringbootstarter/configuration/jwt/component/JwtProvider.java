package kr.sproutfx.common.sproutfxcommonsecurityspringbootstarter.configuration.jwt.component;

import java.util.Base64;
import java.util.Date;

import org.apache.commons.lang3.StringUtils;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import kr.sproutfx.common.sproutfxcommonsecurityspringbootstarter.configuration.jwt.property.AuthorizationProperties;

public class JwtProvider {
    private AuthorizationProperties authorizationProperties;

    public JwtProvider(AuthorizationProperties authorizationProperties) {
        this.authorizationProperties = authorizationProperties;
    }

    public String getAuthorizationHeader() {
        return this.authorizationProperties.getHeader();
    }

    public String getAuthorizationType() {
        return this.authorizationProperties.getType();
    }

    private String createToken(String subject, String audience, byte[] base64DecodedSecret, long validityInSeconds) {
        if (StringUtils.isBlank(subject)) return StringUtils.EMPTY;
        if (validityInSeconds <= 0) return StringUtils.EMPTY;
        if (base64DecodedSecret == null || base64DecodedSecret.length <= 0) return StringUtils.EMPTY;

        return Jwts
            .builder()
            .setSubject(subject)
            .setIssuer(this.authorizationProperties.getProviderCode())
            .setAudience(audience)
            .setNotBefore(new Date())
            .setIssuedAt(new Date())
            .setExpiration(new Date(new Date().getTime() + (validityInSeconds * 1000L)))
            .signWith(Keys.hmacShaKeyFor(base64DecodedSecret), SignatureAlgorithm.HS512)
            .compact();
    }

    public String createToken(String subject, String audience, String secret, long validityInSeconds) {
        return this.createToken(subject, audience, this.convertBase64DecodedSecret(secret), validityInSeconds);
    }

    private Boolean validateToken(byte[] base64DecodedSecret, String audience, String token) {
        try {
            if (StringUtils.isBlank(token)) return false;
            if (base64DecodedSecret == null || base64DecodedSecret.length <= 0) return false;

            return Jwts.parserBuilder()
                .setSigningKey(Keys.hmacShaKeyFor(base64DecodedSecret))
                .build()
                .parseClaimsJws(this.removePrefixOfToken(token))
                .getBody()
                .getAudience()
                .equals(audience);
        } catch (Exception exception) {
            return false;
        }
    }

    public Boolean validateToken(String secret, String audience, String token) {
        if (StringUtils.isBlank(secret) || StringUtils.isBlank(token)) return false;
        return this.validateToken(this.convertBase64DecodedSecret(secret), audience, token);
    }

    public Boolean validateAccessToken(String accessToken) {
        return this.validateToken(this.authorizationProperties.getAccessTokenSecret(), this.authorizationProperties.getClientCode(), accessToken);
    }

    private String extractSubject(byte[] base64DecodedSecret, String audience, String token) {
        if (Boolean.FALSE.equals(this.validateToken(base64DecodedSecret, audience, token))) return null;

        return Jwts
            .parserBuilder()
            .setSigningKey(Keys.hmacShaKeyFor(base64DecodedSecret))
            .build()
            .parseClaimsJws(this.removePrefixOfToken(token))
            .getBody()
            .getSubject();
    }

    public String extractSubject(String secret, String audience, String token) { 
        if (StringUtils.isBlank(secret) || StringUtils.isBlank(token)) return null;
        return this.extractSubject(this.convertBase64DecodedSecret(secret), audience, token);
    }

    public String extractSubjectFromAccessToken(String accessToken) {
        return this.extractSubject(this.authorizationProperties.getAccessTokenSecret(), this.authorizationProperties.getClientCode(), accessToken);
    }

    public Date extractExpiration(String secret, String audience, String token) {
        if (StringUtils.isBlank(secret) || StringUtils.isBlank(token)) return null;
        return this.extractExpiration(this.convertBase64DecodedSecret(secret), audience, token);
    }

    private Date extractExpiration(byte[] base64DecodedSecret, String audience, String token) {
        if (Boolean.FALSE.equals(this.validateToken(base64DecodedSecret, audience, token))) return null;

        return Jwts
            .parserBuilder()
            .setSigningKey(Keys.hmacShaKeyFor(base64DecodedSecret))
            .build()
            .parseClaimsJws(this.removePrefixOfToken(token))
            .getBody()
            .getExpiration();
    }

    public Long extractExpiresInSeconds(byte[] base64DecodedSecret, String audience, String token) {
        return this.convertExpirationToExpiresInSeconds(this.extractExpiration(base64DecodedSecret, audience, token));
    }

    public Long extractExpiresInSeconds(String secret, String audience, String token) {
        return this.convertExpirationToExpiresInSeconds(this.extractExpiration(this.convertBase64DecodedSecret(secret), audience, token));
    }

    public Date extractExpirationFromAccessToken(String accessToken) {
        return this.extractExpiration(this.authorizationProperties.getAccessTokenSecret(), this.authorizationProperties.getClientCode(), accessToken);
    }

    public Long extractExpiresInSecondsFromAccessToken(String accessToken) {
        return this.convertExpirationToExpiresInSeconds(this.extractExpirationFromAccessToken(accessToken));
    }

    public String removePrefixOfToken(String token) {
        String tokenPrefix = this.getAuthorizationType();

        if (StringUtils.isNotBlank(token) && token.contains(tokenPrefix)) {
            return token.substring(tokenPrefix.length()).trim();
        } else if (StringUtils.isNotBlank(token)) {
            return token.trim();
        } else {
            return token;
        }
    }

    private Long convertExpirationToExpiresInSeconds(Date expiration) {
        return expiration == null ? -1 : (expiration.getTime() - new Date(System.currentTimeMillis()).getTime()) / 1000;
    }

    private byte[] convertBase64DecodedSecret(String secret) {
        return Decoders.BASE64.decode(Base64.getEncoder().encodeToString(secret.getBytes()));
    }

}
