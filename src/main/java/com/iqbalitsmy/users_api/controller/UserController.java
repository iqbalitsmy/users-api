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

/**
 * ================================================================
 * STEP 18: USER CONTROLLER — Protected Profile & Admin Endpoints
 * ================================================================
 *
 * ALL endpoints here require a valid JWT in the Authorization header.
 * The JwtAuthenticationFilter validates the token and sets SecurityContext
 * before any method here runs.
 *
 * ── ENDPOINTS ────────────────────────────────────────────────────
 *  GET    /api/users/me          → own profile (any authenticated user)
 *  PUT    /api/users/me          → update own name (any authenticated user)
 *  GET    /api/users/all         → all users (ADMIN only)
 *  GET    /api/users/{id}        → any user by ID (ADMIN only)
 *  DELETE /api/users/{id}        → deactivate user (ADMIN only)
 *
 * WHY /me for own profile instead of /api/users/{id}?
 * The user doesn't need to know their own ID.
 * They just send their JWT and get their own profile back.
 * /me is a widely used convention (GitHub API, Spotify API, etc.)
 *
 * INTERVIEW TIP — "What is the difference between URL-level and
 * method-level security?"
 *  URL-level  → SecurityConfig .authorizeHttpRequests() — coarse-grained,
 *               good for "all GET requests on /admin/**"
 *  Method-level → @PreAuthorize on the method — fine-grained,
 *                 good for "only ADMIN can call THIS method regardless of URL"
 * Using BOTH is called "defense in depth".
 */

@RestController
@RequestMapping("/api/users")
@RequiredArgsConstructor
@Slf4j
public class UserController {
    private final UserService userService;

    // ── GET /api/users/me — Own profile ──────────────────────────
    /*
     * WHY read email from SecurityContext (not URL param)?
     * SecurityContext holds the email from the validated JWT.
     * It's tamper-proof — the JWT filter set it after signature verification.
     * If we accepted the email as a URL param, a user could request
     * someone else's profile just by changing the param.
     */
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
