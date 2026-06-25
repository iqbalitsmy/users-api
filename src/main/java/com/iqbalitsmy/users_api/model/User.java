package com.iqbalitsmy.users_api.model;

import jakarta.persistence.*;
import jakarta.validation.constraints.Email;
import lombok.*;

/**
 * ================================================================
 * STEP 2: USER ENTITY
 * ================================================================
 *
 * WHY @Entity?
 * Marks this class as a JPA entity — maps directly to a DB table.
 * Each instance = one row. Each field = one column.
 * Hibernate reads these annotations and generates CREATE TABLE SQL.
 *
 * WHY @Table(name = "users")?
 * "user" is a reserved keyword in H2/SQL. "users" avoids conflicts.
 *
 * ── CRITICAL DESIGN DECISION ────────────────────────────────────
 * This User entity must support TWO completely different sign-up paths:
 *
 *   Path A — LOCAL (email + password):
 *     email    = provided by user
 *     password = BCrypt hash of user's password
 *     provider = AuthProvider.LOCAL
 *     providerId = null
 *
 *   Path B — OAUTH2 (Google / GitHub):
 *     email      = from Google/GitHub profile
 *     password   = null (they never set one — they log in via the provider)
 *     provider   = AuthProvider.GOOGLE or AuthProvider.GITHUB
 *     providerId = the user's unique ID at that provider (e.g., Google subject "1234567890")
 *
 * WHY store providerId?
 * When a user logs in with Google again, we need to find THEIR account.
 * We match on (provider, providerId) — not just email — because:
 *  - Email can change at the provider
 *  - Different providers could share the same email (edge case)
 *  - providerId is the stable, immutable identifier at each provider
 *
 * INTERVIEW TIP — "What is an @Enumerated field?"
 * Stores a Java enum in the DB. STRING stores the name ("GOOGLE"),
 * ORDINAL stores the position (0, 1, 2...). Always use STRING —
 * if you add enum values, ORDINAL positions shift and data corrupts.
 */



@Entity
@Table(name="users")
@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class User {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    /*
     * WHY nullable = true (no nullable=false)?
     * Some OAuth2 providers (rare) may not share email.
     * We allow null here and handle it in the OAuth2 user service.
     */
    @Email(message = "Enter valid email")
    @Column(unique = true, nullable = false, length = 150)
    private String email;

    @Column(nullable = false, length = 100)
    private String name;

    @Column(length = 200)
    private String imageUrl;
    /*
     * WHY nullable? (password can be null)
     * OAuth2 users NEVER set a password. They authenticate via their
     * provider (Google, GitHub). Having a null password for them is correct.
     * We must never allow null-password users to use the local login endpoint.
     * That check is enforced in AuthService.login().
     */
    @Column
    private String password;

    @Column(nullable = false)
    private boolean emailVerified =false;
    /*
     * WHY emailVerified?
     * Local users: we'd normally send a verification email. For this project,
     * we set it true on registration.
     * OAuth2 users: Google/GitHub already verified the email — set true automatically.
     */

    /*
     * WHY @Enumerated(EnumType.STRING)?
     * Stores "LOCAL", "GOOGLE", "GITHUB" as strings in the DB.
     * Much safer than ORDINAL — adding new providers won't corrupt data.
     *
     * provider tells us HOW this user authenticates:
     *  - LOCAL  → they have a password in this DB
     *  - GOOGLE → they authenticate via Google OAuth2
     *  - GITHUB → they authenticate via GitHub OAuth2
     */
    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 20)
    private AuthProvider provider;
    /*
     * WHY providerId?
     * The unique user ID assigned by the OAuth2 provider.
     * Google: "sub" claim in their ID token (e.g., "107312345678901234567")
     * GitHub: numeric user ID (e.g., "12345678")
     *
     * On subsequent logins, we find the user by (provider + providerId)
     * and update their profile info (name, picture may change).
     */
    @Column
    private String providerId;

    @Column(nullable = false, length = 20)
    @Builder.Default
    private String role = "ROLE_USER";

    @Column(nullable = false)
    @Builder.Default
    private boolean active=true;
}
