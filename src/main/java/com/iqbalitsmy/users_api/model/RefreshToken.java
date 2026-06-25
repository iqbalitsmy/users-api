package com.iqbalitsmy.users_api.model;

import jakarta.persistence.*;
import lombok.*;

import java.time.Instant;

/**
 * ================================================================
 * REFRESH TOKEN ENTITY
 * ================================================================
 *
 * WHY a separate RefreshToken entity?
 * Access tokens are short-lived (15 min) — they expire quickly.
 * Without refresh tokens, users would have to log in every 15 minutes.
 * The refresh token (7 days) lets the client silently get a new
 * access token without asking the user for credentials again.
 *
 * WHY persist refresh tokens in the DATABASE?
 * This is critical — here's why:
 *
 *   JWT access tokens → stateless, server stores NOTHING
 *   Refresh tokens    → stateful, server stores them in DB
 *
 * Why persist refresh tokens specifically?
 *  1. LOGOUT: When the user logs out, we DELETE the refresh token from DB.
 *             Their access token may still be valid (up to 15 min), but
 *             they CANNOT get a new one → effectively logged out.
 *  2. REVOCATION: If a token is stolen, we can delete it from DB immediately.
 *  3. ROTATION: We can enforce "one active refresh token per user" policy.
 *
 * INTERVIEW TIP — "How do you implement logout with JWT?"
 * You can't invalidate a JWT before expiry (it's stateless/self-contained).
 * Solution: short access token (15 min) + persisted refresh token.
 * Logout = delete the refresh token from DB.
 * The access token expires naturally after 15 min.
 * For instant invalidation: add the access token ID to a Redis denylist.
 *
 * WHY @OneToOne(fetch = LAZY)?
 * Each refresh token belongs to exactly one user.
 * LAZY = don't load the User object until we explicitly access it.
 * EAGER would load User every time we load a RefreshToken — wasteful
 * when all we need is the token string for validation.
 */

@Entity
@Table(name = "refresh_tokens")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class RefreshToken {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    /*
     * WHY @OneToOne with @JoinColumn?
     * One user ↔ one active refresh token (we enforce this in the service).
     * @JoinColumn(name = "user_id") creates a foreign key column user_id
     * in the refresh_tokens table pointing to users.id.
     *
     * FETCH.LAZY: Only load the User when we call .getUser() — not automatically.
     */
    @OneToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", referencedColumnName = "id")
    private User user;

    @Column(nullable = false, unique = true, length = 500)
    private String token;
    /*
     * WHY Instant for expiryDate?
     * Instant is the best Java type for timestamps:
     *  - Stores UTC (no timezone confusion)
     *  - Comparable with Instant.now() for expiry checks
     *  - Maps cleanly to TIMESTAMP in SQL
     */
    @Column(nullable = false)
    private Instant expiryDate;

    public boolean  isExpired() {
        return Instant.now().isAfter(this.expiryDate);
    }
}


