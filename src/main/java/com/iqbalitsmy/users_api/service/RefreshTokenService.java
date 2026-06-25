package com.iqbalitsmy.users_api.service;

import com.iqbalitsmy.users_api.exception.AppExceptions;
import com.iqbalitsmy.users_api.model.RefreshToken;
import com.iqbalitsmy.users_api.model.User;
import com.iqbalitsmy.users_api.repository.RefreshTokenRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.UUID;

/**
 * ================================================================
 * STEP 12: REFRESH TOKEN SERVICE
 * ================================================================
 *
 * WHY a dedicated service for refresh tokens?
 * Refresh tokens are a security-sensitive, independently managed concern.
 * Separating them from AuthService keeps each class focused and testable.
 *
 * ── REFRESH TOKEN LIFECYCLE ──────────────────────────────────────
 *
 *  CREATE  → on login (local or OAuth2), generate + save to DB
 *  VERIFY  → on POST /auth/refresh, find in DB + check expiry
 *  ROTATE  → after successful refresh, delete old + create new
 *            (prevents "refresh token reuse" attacks)
 *  DELETE  → on logout, remove from DB immediately
 *            (this is what makes logout effective for JWT)
 *
 * ── WHY ROTATION? ────────────────────────────────────────────────
 * If an attacker steals a refresh token, they can get access tokens
 * indefinitely. With rotation:
 *  - Every /auth/refresh call invalidates the old token
 *  - A stolen token can only be used ONCE before it's rotated away
 *  - If both the attacker and real user try to use the same token,
 *    the second attempt fails → signals a potential breach
 *
 * INTERVIEW TIP — "Why is refresh token stateful but access token stateless?"
 * Access tokens: server stores NOTHING. Verify by checking JWT signature.
 *   Fast — no DB call needed. Risk: can't revoke early.
 * Refresh tokens: stored in DB. Verify by finding the token record.
 *   Slower — requires DB lookup. Benefit: can revoke instantly (delete row).
 * This hybrid approach balances performance with security.
 */

@Service
@RequiredArgsConstructor
@Slf4j
public class RefreshTokenService {
    private final RefreshTokenRepository refreshTokenRepository;

    @Value("${app.jwt.refresh-token-expiry-ms}")
    private long refreshTokenExpiryMs;

    // ── CREATE ───────────────────────────────────────────────────

    /*
     * WHY @Transactional?
     * We first delete any existing token, then save a new one.
     * Both operations must succeed or both roll back.
     * Without @Transactional, a crash between delete and save
     * would leave the user with NO valid refresh token.
     */
    @Transactional
    public RefreshToken createRefreshToken(User user) {
        log.info("Creating refresh token for user: {}", user.getEmail());

        /*
         * WHY delete existing token first?
         * We enforce ONE active refresh token per user.
         * If we didn't delete, a user who logs in twice would have
         * two valid refresh tokens — doubles the attack surface.
         * Old token out → new token in.
         */
        refreshTokenRepository.deleteByUser(user);

        RefreshToken token = RefreshToken.builder()
                /*
                 * WHY UUID.randomUUID().toString()?
                 * Refresh tokens are OPAQUE — they carry no data, unlike JWTs.
                 * UUID is a cryptographically random 128-bit value.
                 * It's unguessable and unique — attackers can't predict or
                 * brute-force it. The DB validates it, not a signature.
                 *
                 * WHY not another JWT for the refresh token?
                 * We WANT it to be stateful (stored in DB) so we can revoke it.
                 * JWTs are self-contained and can't be revoked without a denylist.
                 * An opaque random string that lives in our DB gives us full control.
                 */
                .user(user).token(UUID.randomUUID().toString())
                .expiryDate(Instant.now().plusMillis(refreshTokenExpiryMs))
                .build();
        return refreshTokenRepository.save(token);
    }

    // ── VERIFY ───────────────────────────────────────────────────
    /*
     * WHY findAndValidate() as one operation?
     * "Find" and "check expiry" always go together.
     * Splitting them risks using a token after finding but before checking.
     * Combining into one method enforces the correct usage pattern.
     */
    public RefreshToken findAndValidate(String token) {
        RefreshToken refreshToken = refreshTokenRepository.findByToken(token)
                .orElseThrow(() -> {
                            log.warn("Refresh token is not found in DB - may have been used or logged out");
                    /*
                     * WHY TokenRefreshException (not InvalidCredentialsException)?
                     * These are distinct failure reasons.
                     * "Token not found" means: already used (rotation), or logged out.
                     * The client needs to know to redirect to login — not retry.
                     */
                            return new AppExceptions.InvalidTokenRefreshException("Refresh token not found. Please log in again.");
                        }
                );

        if (refreshToken.isExpired()) {
            log.warn("Expired refresh token used for user: {}", refreshToken.getUser().getEmail());
            /*
             * WHY delete the expired token?
             * Cleanup — expired tokens in the DB are dead weight.
             * Also prevents confusion: if the token were left in DB,
             * a future look-up would find it but always fail the expiry check.
             * Better to remove it so the "token not found" path triggers instead.
             */
            refreshTokenRepository.delete(refreshToken);
            throw new AppExceptions.InvalidTokenRefreshException("Refresh token has been expired. Please login again.");
        }

        return refreshToken;
    }

    // ── ROTATE ───────────────────────────────────────────────────

    /*
     * WHY rotateRefreshToken()?
     * Called after a successful /auth/refresh request.
     * Old token is deleted, brand new token is created and returned.
     * The client MUST store the new token and discard the old one.
     * Any subsequent refresh must use the new token.
     */
    @Transactional
    public RefreshToken rotateRefreshToken(RefreshToken oldToken) {
        log.debug("Rotating refresh token for user: {}", oldToken.getUser().getEmail());

        refreshTokenRepository.delete(oldToken);
        return createRefreshToken(oldToken.getUser());
    }

    // ── DELETE (LOGOUT) ──────────────────────────────────────────
    /*
     * WHY deleteByUser()?
     * This is LOGOUT. Removing the refresh token from DB means:
     *  - The user cannot get new access tokens
     *  - Their current access token expires naturally in ~15 min
     *  - For immediate invalidation: also add access token to Redis denylist
     *
     * @Transactional: ensures the delete is committed atomically.
     * If the delete fails, the transaction rolls back — user is not logged out.
     * This is the safe behaviour (fail open for logout, not fail closed).
     */
    @Transactional
    public void deleteByUser(User user) {
        log.info("Deleting refresh token for user (logout): {}", user.getEmail());
        refreshTokenRepository.deleteByUser(user);
    }
}
