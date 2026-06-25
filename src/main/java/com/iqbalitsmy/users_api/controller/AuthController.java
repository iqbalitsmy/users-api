package com.iqbalitsmy.users_api.controller;

import com.iqbalitsmy.users_api.Dto.AuthDto;
import com.iqbalitsmy.users_api.exception.AppExceptions;
import com.iqbalitsmy.users_api.service.AuthService;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import java.time.Duration;
import java.util.Map;


/**
 * ================================================================
 * STEP 17: AUTH CONTROLLER — Identity Endpoints
 * ================================================================
 *
 * WHY @RestController?
 * Combines @Controller + @ResponseBody.
 * Every method return value is auto-serialised to JSON via Jackson.
 *
 * WHY @RequestMapping("/auth")?
 * Groups all authentication endpoints. These are PERMIT_ALL in
 * SecurityConfig — no JWT required (chicken-and-egg problem).
 *
 * ── ENDPOINTS IN THIS CONTROLLER ────────────────────────────────
 *
 *  POST /auth/register  → create local account + receive tokens
 *  POST /auth/login     → local login with email/password + receive tokens
 *  POST /auth/refresh   → exchange refresh token for new access token
 *  POST /auth/logout    → delete refresh token (invalidate session)
 *
 * ── SOCIAL LOGIN ENDPOINTS (NOT in this controller) ──────────────
 * Social login is handled entirely by Spring Security's OAuth2 machinery:
 *
 *  GET /oauth2/authorization/google
 *    → Spring redirects user to Google's consent screen
 *    → No code needed — auto-registered by spring-boot-starter-oauth2-client
 *
 *  GET /oauth2/authorization/github
 *    → Spring redirects user to GitHub's consent screen
 *
 *  GET /login/oauth2/code/google  (Google's callback URI)
 *  GET /login/oauth2/code/github  (GitHub's callback URI)
 *    → Spring handles the authorization code exchange
 *    → Calls CustomOAuth2UserService.loadUser()
 *    → Calls OAuth2AuthenticationSuccessHandler on success
 *    → Issues our JWT + redirects to frontend
 */
@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
@Slf4j
public class AuthController {
    public final AuthService authService;

    // ── POST /auth/register ───────────────────────────────────────
    @PostMapping("/register")
    public ResponseEntity<AuthDto.TokenResponse> register(@Valid @RequestBody AuthDto.RegisterRequest request) {
        log.info("POST /auth/register for :{}", request.getEmail());

        return ResponseEntity.status(HttpStatus.CREATED).body(authService.register(request));
    }

    // ── POST /auth/login ──────────────────────────────────────────
    @PostMapping("/login")
    public ResponseEntity<AuthDto.TokenResponse> login(@Valid @RequestBody AuthDto.LoginRequest request, HttpServletResponse response) {
        log.info("POST /auth/login for :{}", request.getEmail());

        AuthDto.TokenResponse result = authService.login(request);
        setRefreshTokenCookie(response, result.getRefreshToken());
        return ResponseEntity.ok(result);
    }

    // ── POST /auth/refresh ────────────────────────────────────────
    @PostMapping("/refresh")
    public ResponseEntity<AuthDto.TokenResponse> refresh(@CookieValue(name = "refreshToken", required = false) String refreshTokenCookie, HttpServletResponse response) {
        log.info("POST /auth/refresh");
        if (refreshTokenCookie == null) {
            throw new AppExceptions.InvalidTokenRefreshException("Refresh token missing.");
        }

        AuthDto.TokenResponse result = authService.refresh(refreshTokenCookie);

        setRefreshTokenCookie(response, result.getRefreshToken());

        AuthDto.TokenResponse tokenResponse = AuthDto.TokenResponse.builder()
                .accessToken(result.getAccessToken())
                .accessTokenExpireIn(result.getAccessTokenExpireIn())
                .email(result.getEmail())
                .role(result.getRole())
                .provider(result.getProvider())
                .build();

        return ResponseEntity.ok(tokenResponse);
    }

    // ── POST /auth/logout ─────────────────────────────────────────
    @PostMapping("/logout")
    public ResponseEntity<Void> logout(HttpServletResponse response) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();

        String email = auth.getName();
        log.info("POST /auth/logout for :{}", email);

        authService.logout(email);
        ResponseCookie deleteCookie = ResponseCookie.from("refreshToken", "")
                .httpOnly(true)
                .secure(true)
                .path("/auth")
                .maxAge(0)
                .sameSite("Strict")
                .build();
        response.addHeader(HttpHeaders.SET_COOKIE, deleteCookie.toString());

        return ResponseEntity.noContent().build();
    }

    // ── GET /auth/success ──────────────────────────────────────────
    @GetMapping("/success")
    public ResponseEntity<String> loginSuccess() {
        log.info("GET /auth/success");

        return ResponseEntity.status(HttpStatus.CREATED).body("Success");
    }

    private void setRefreshTokenCookie(HttpServletResponse response, String token) {
        ResponseCookie cookie = ResponseCookie.from("refreshToken", token)
                .httpOnly(true)
                .secure(true)
                .path("/auth")
                .maxAge(Duration.ofDays(7))
                .sameSite("strict")
                .build();
        response.addHeader(HttpHeaders.SET_COOKIE, cookie.toString());
    }

}
