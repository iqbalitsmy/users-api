package com.iqbalitsmy.users_api.security.oauth2;

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

/*
 * ── REFRESH TOKEN LIFECYCLE ──────────────────────────────────────
 *
 *  CREATE  → on login (local or OAuth2), generate + save to DB
 *  VERIFY  → on POST /auth/refresh, find in DB + check expiry
 *  ROTATE  → after successful refresh, delete old + create new
 *            (prevents "refresh token reuse" attacks)
 *  DELETE  → on logout, remove from DB immediately
 *            (this is what makes logout effective for JWT)
 * */

@Service
@RequiredArgsConstructor
@Slf4j
public class RefreshTokenService {
    private final RefreshTokenRepository refreshTokenRepository;

    @Value("${app.jwt.refresh-token-expiry-ms}")
    private long refreshTokenExpiryMs;

    // ── CREATE ───────────────────────────────────────────────────
    @Transactional
    public RefreshToken createRefreshToken(User user) {
        log.info("Creating refresh token for user: {}", user.getEmail());

        refreshTokenRepository.deleteByUser(user);

        RefreshToken token = RefreshToken.builder()
                .user(user).token(UUID.randomUUID().toString())
                .expiryDate(Instant.now().plusMillis(refreshTokenExpiryMs))
                .build();
        return refreshTokenRepository.save(token);
    }

    // ── VERIFY ───────────────────────────────────────────────────
    public RefreshToken findAndValidate(String token) {
        RefreshToken refreshToken = refreshTokenRepository.findByToken(token)
                .orElseThrow(() -> {
                            log.warn("Refresh token is not found in DB - may have been used or logged out");
                            return new AppExceptions.InvalidTokenRefreshException("Refresh token not found. Please log in again.");
                        }
                );

        if (refreshToken.isExpired()) {
            log.warn("Expired refresh token used for user: {}", refreshToken.getUser().getEmail());

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
    @Transactional
    public void deleteByUser(User user) {
        log.info("Deleting refresh token for user (logout): {}", user.getEmail());
        refreshTokenRepository.deleteByUser(user);
    }
}
