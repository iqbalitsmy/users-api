package com.iqbalitsmy.users_api.controller;

import com.iqbalitsmy.users_api.Dto.AuthDto;
import com.iqbalitsmy.users_api.service.AuthService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

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
    public ResponseEntity<AuthDto.TokenResponse> login(@Valid @RequestBody AuthDto.LoginRequest request) {
        log.info("POST /auth/login for :{}", request.getEmail());

        return ResponseEntity.ok(authService.login(request));
    }

    // ── POST /auth/refresh ────────────────────────────────────────
    @PostMapping("/refresh")
    public ResponseEntity<AuthDto.TokenResponse> refresh(@Valid @RequestBody AuthDto.RefreshRequest request) {
        log.info("POST /auth/refresh");

        return ResponseEntity.ok(authService.refresh(request));
    }

    // ── POST /auth/logout ─────────────────────────────────────────
    @PostMapping("/logout")
    public ResponseEntity<Void> logout() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();

        String email = auth.getName();
        log.info("POST /auth/logout for :{}", email);

        authService.logout(email);
        return ResponseEntity.noContent().build();
    }

}
