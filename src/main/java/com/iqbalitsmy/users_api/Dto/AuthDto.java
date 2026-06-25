package com.iqbalitsmy.users_api.Dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.*;
/**
 * ================================================================
 * STEP 4: DATA TRANSFER OBJECTS (DTOs)
 * ================================================================
 *
 * WHY DTOs instead of using the @Entity directly?
 *
 *  1. SECURITY    — Never expose password (even BCrypt hash) to clients.
 *                   Never expose provider credentials.
 *
 *  2. DECOUPLING  — API contract is independent of DB schema.
 *                   Rename a column? DTO stays the same for clients.
 *
 *  3. VALIDATION  — Enforce rules on incoming data (@Email, @Size)
 *                   before it touches business logic or the DB.
 *
 *  4. FLEXIBILITY — Different operations need different shapes.
 *                   LoginRequest ≠ RegisterRequest ≠ UserResponse.
 *
 * We use inner static classes to group related DTOs.
 * In larger projects, split into separate files per domain.
 */

public class AuthDto {
    // ── REGISTER ─────────────────────────────────────────────────
    // WHY: Client sends name + email + password to POST /auth/register.
    // This only applies to LOCAL provider registration.
    // OAuth2 users register automatically via the social login flow.
    @Getter
    @Setter
    @AllArgsConstructor
    @NoArgsConstructor
    @Builder
    public  static class RegisterRequest{
        @NotBlank(message = "Name is required")
        @Size(min = 2, max = 100, message = "Name must be 2-100 character")
        private String name;

        @NotBlank(message = "Email is required")
        @Email(message = "Email must be valid formate")
        private String email;

        @NotBlank(message = "Password is required")
        @Size(min = 3, max = 100, message = "Password must be at least character")
        private String password;
    }

    // ── LOGIN ─────────────────────────────────────────────────────
    // WHY: Client sends email + password to POST /auth/login.
    // Only for LOCAL provider users. OAuth2 users use /oauth2/authorization/{provider}.
    @Getter
    @Setter
    @AllArgsConstructor
    @NoArgsConstructor
    @Builder
    public  static class LoginRequest{

        @NotBlank(message = "Email is required")
        @Email(message = "Email must be valid formate")
        private String email;

        @NotBlank(message = "Password is required")
        private String password;
    }

    // ── TOKEN RESPONSE ────────────────────────────────────────────
    // WHY: Returned after successful login (both local AND OAuth2).
    // Contains access token + refresh token + metadata.
    //
    // WHY TWO tokens?
    // accessToken  = short-lived JWT (15 min). Sent in Authorization header.
    //                Stateless — server stores nothing.
    // refreshToken = long-lived opaque string (7 days). Stored in DB.
    //                Sent to POST /auth/refresh to get a new access token.
    //                Deleted from DB on logout — this is how logout works.
    @Getter
    @Setter
    @AllArgsConstructor
    @NoArgsConstructor
    @Builder
    public static class TokenResponse{
        private String accessToken;
        private String refreshToken;
        private String tokenType="Bearer";
        private long accessTokenExpireIn;
        private String email;
        private String role;
        private String provider;
    }
    // ── REFRESH REQUEST ───────────────────────────────────────────
    // WHY: Client sends the refresh token to POST /auth/refresh.
    // Server validates it, returns a new access token (and rotates refresh token).
    @Getter
    @Setter
    @AllArgsConstructor
    @NoArgsConstructor
    @Builder
    public static class RefreshRequest{
        @NotBlank(message = "Refresh token is required")
        private String refreshToken;
    }

    // ── USER RESPONSE ─────────────────────────────────────────────
    // WHY: What we send back when a client requests user profile data.
    // NEVER includes password. Includes provider info (useful for the frontend).
    @Getter
    @Setter
    @AllArgsConstructor
    @NoArgsConstructor
    @Builder
    public static class  UserResponse{
        private Long id;
        private String name;
        private String email;
        private String imageUrl;
        private boolean emailVerified;
        private String role;
        private String provider;
        private boolean active;
    }

    // ── UPDATE PROFILE ────────────────────────────────────────────
    // WHY: Users can update their name. Email changes require re-verification.
    // OAuth2 users can also update their name (overrides what Google/GitHub sent).
    @Getter
    @Setter
    @AllArgsConstructor
    @NoArgsConstructor
    @Builder
    public static class UpdateProfileRequest{
        @NotBlank(message = "Name is required")
        @Size(min = 2, max = 100, message = "Name must be 2-100 character")
        private String name;
    }
}
