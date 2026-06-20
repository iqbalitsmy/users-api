package com.iqbalitsmy.users_api.controller;

import com.iqbalitsmy.users_api.Dto.AuthDto;
import com.iqbalitsmy.users_api.service.UserService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/users")
@RequiredArgsConstructor
@Slf4j
public class UserController {
    private final UserService userService;

    // ── GET /api/users/me — Own profile ──────────────────────────
    @GetMapping("/me")
    public ResponseEntity<AuthDto.UserResponse> getProfile() {
        String email = getCurrentUserEmail();
        log.info("GET /api/users/me for :{}", email);

        return ResponseEntity.ok(userService.getUser(email));
    }

    // ── PUT /api/users/me — Update own profile ────────────────────
    @PutMapping("/me")
    public ResponseEntity<AuthDto.UserResponse> updateProfile(@Valid @RequestBody AuthDto.UpdateProfileRequest request) {
        String email = getCurrentUserEmail();
        log.info("PUT /api/users/me for :{}", email);

        return ResponseEntity.ok(userService.updateProfile(email, request));
    }

    // ── GET /api/users/all — List all users (ADMIN) ───────────────
    @GetMapping("/all")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<List<AuthDto.UserResponse>> getAllUsers() {
        log.info("GET /api/users/all");

        return ResponseEntity.ok(userService.getAllUsers());
    }

    // ── GET /api/users/{id} — Get any user by ID (ADMIN) ─────────
    @GetMapping("/{id}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<AuthDto.UserResponse> getUserById(@PathVariable Long id) {
        log.info("GET /api/users/{}", id);
        return ResponseEntity.ok(userService.getUserById(id));
    }

    // ── DELETE /api/users/{id} — Deactivate user (ADMIN) ─────────
    @DeleteMapping("/{id}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Void> deactivateUser(@PathVariable Long id) {
        log.info("DELETE /api/users/{}", id);
        userService.deactivateUser(id);
        return ResponseEntity.noContent().build();
    }

    // ── PRIVATE HELPER ────────────────────────────────────────────
    private String getCurrentUserEmail() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        return authentication.getName();
    }


}
