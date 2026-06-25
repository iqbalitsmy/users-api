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

/**
 * ================================================================
 * STEP 6: JWT SERVICE
 * ================================================================
 *
 * WHY a dedicated JwtService?
 * All JWT logic (create, sign, parse, validate) lives here.
 * Controllers, filters, and other services call this without
 * knowing anything about the JWT library (jjwt) internals.
 * If we swap jjwt for another library, only this class changes.
 *
 * ── WHAT IS A JWT? ───────────────────────────────────────────────
 *
 *  eyJhbGciOiJIUzI1NiJ9  .  eyJzdWIiOiJ1c2VyQGUuY29tIn0  .  SflKxwRJSMeKKF2QT
 *  └────── HEADER ──────┘   └──────────── PAYLOAD ──────────┘  └── SIGNATURE ───┘
 *
 *  HEADER   → {"alg":"HS256"} — algorithm used to sign
 *  PAYLOAD  → {"sub":"email","role":"ROLE_USER","provider":"GOOGLE","iat":...,"exp":...}
 *  SIGNATURE → HMAC_SHA256(base64(header) + "." + base64(payload), secretKey)
 *
 * ── WHY WE ISSUE OUR OWN JWT AFTER OAUTH2 LOGIN ──────────────────
 * After Google/GitHub authenticates the user, Spring Security gives us an
 * OAuth2 session — but that's browser/session based (not REST-friendly).
 * We immediately convert it to our own short-lived JWT so that:
 *  - The API remains fully stateless
 *  - Mobile clients and React apps can use standard Bearer tokens
 *  - The frontend doesn't need to know about the OAuth2 internals
 *  - All downstream API calls use the same token format regardless of
 *    whether the user signed in locally or via Google/GitHub
 */
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

    /*
     * WHY put role and provider in the token claims?
     * So the server can make authorization decisions (role check) and
     * the client can display "logged in via Google" — all without a DB call.
     * The token is self-describing.
     */
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

    public long getAccessTokenExpiryMs() {
        return accessTokenExpiryMs;
    }

    /*
     * WHY decode from Base64 each call?
     * @Value is injected AFTER object construction.
     * We can't do `private final SecretKey key = getSigningKey()`
     * at field declaration time — jwtSecret would be null.
     * Decoding per-call is safe; or use @PostConstruct to cache it.
     */
    private SecretKey getSigningKey() {
        byte[] keyBytes = Decoders.BASE64.decode(jwtSecret);
        return Keys.hmacShaKeyFor(keyBytes);
    }
}
