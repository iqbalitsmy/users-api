package com.iqbalitsmy.users_api.security.jwt;

import com.iqbalitsmy.users_api.exception.AppExceptions;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;


@Service
@Slf4j
public class JwtService {
    @Value("${app.jwt.secret}")
    private String jwtSecret;

    @Value("${app.jwt.access-token-expiry-ms}")
    private long accessTokenExpiryMs;

    // ── TOKEN GENERATION ─────────────────────────────────────────
    public String generateAccessToken(UserDetails userDetails) {
        return generateAccessToken(new HashMap<>(), userDetails);
    }

    private String generateAccessToken(Map<String, Object> extraClaims, UserDetails userDetails) {
        extraClaims.put("role", userDetails.getAuthorities().stream()
                .findFirst()
                .map(a -> a.getAuthority())
                .orElse("ROLE_USER"));

        return Jwts.builder()
                .claims(extraClaims)
                .subject(userDetails.getUsername())
                .issuedAt(new Date(System.currentTimeMillis()))
                .expiration(new Date(System.currentTimeMillis() + getAccessTokenExpiryMs()))
                .signWith(getSigningKey())
                .compact();
    }

    // ── TOKEN VALIDATION ─────────────────────────────────────────
    public boolean isTokenValid(String token, UserDetails userDetails) {
        String email = userDetails.getUsername();
        return email.equals(extractEmail(token)) && !isTokenExpired(token);
    }

    private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    // ── CLAIM EXTRACTION ─────────────────────────────────────────

    public String extractEmail(String token) {
        return extractALlClaims(token).getSubject();
    }

    public Date extractExpiration(String token) {
        return extractALlClaims(token).getExpiration();
    }

    private Claims extractALlClaims(String token) {
        try {
            return Jwts.parser().verifyWith(getSigningKey()).build().parseSignedClaims(token).getPayload();
        } catch (ExpiredJwtException e) {
            log.warn("token has expired :{}", e.getMessage());
            throw new AppExceptions.InvalidTokenException("Token has been expired");
        } catch (JwtException e) {
            log.warn("invalid jwt exception :{}", e.getMessage());
            throw new AppExceptions.InvalidTokenException("Token is Invalid");
        }
    }

    private long getAccessTokenExpiryMs() {
        return accessTokenExpiryMs;
    }

    private SecretKey getSigningKey() {
        byte[] keyBytes = Decoders.BASE64.decode(jwtSecret);
        return Keys.hmacShaKeyFor(keyBytes);
    }
}
