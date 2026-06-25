package com.iqbalitsmy.users_api.service;

import com.iqbalitsmy.users_api.Dto.AuthDto;
import com.iqbalitsmy.users_api.exception.AppExceptions;
import com.iqbalitsmy.users_api.model.AuthProvider;
import com.iqbalitsmy.users_api.model.RefreshToken;
import com.iqbalitsmy.users_api.model.User;
import com.iqbalitsmy.users_api.repository.UserRepository;
import com.iqbalitsmy.users_api.security.jwt.JwtService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;


/**
 * ================================================================
 * STEP 13: AUTH SERVICE — Local Auth Business Logic
 * ================================================================
 *
 * WHY a separate AuthService?
 * Auth operations (register, login, refresh, logout) are distinct
 * from user management (CRUD). Separation of Concerns:
 *  - AuthService  → deals with credentials, tokens, sessions
 *  - UserService  → deals with user profile data
 *
 * This service handles the LOCAL auth path only.
 * The OAuth2 path is handled by: CustomOAuth2UserService →
 * OAuth2AuthenticationSuccessHandler → RefreshTokenService.
 *
 * ── LOCAL vs OAUTH2 AUTH COMPARISON ─────────────────────────────
 *
 *  LOCAL PATH:
 *    POST /auth/register → create user with BCrypt password
 *    POST /auth/login    → verify password → issue JWT + refresh token
 *    POST /auth/refresh  → validate refresh token → new JWT + rotate token
 *    POST /auth/logout   → delete refresh token from DB
 *
 *  OAUTH2 PATH:
 *    GET /oauth2/authorization/{provider} → redirect to Google/GitHub
 *    GET /login/oauth2/code/{provider}    → Spring handles code exchange
 *    CustomOAuth2UserService              → find/create user in DB
 *    OAuth2SuccessHandler                 → issue JWT + redirect to frontend
 *    POST /auth/refresh                   → SAME as local (shared endpoint!)
 *    POST /auth/logout                    → SAME as local (shared endpoint!)
 *
 * Refresh and logout work identically for both paths — this is a key
 * design advantage of issuing our own JWT after OAuth2 login.
 */

@Service
@RequiredArgsConstructor
@Slf4j
public class AuthService {
    private final UserRepository userRepository;
    private final JwtService jwtService;
    private final RefreshTokenService refreshTokenService;
    private final AuthenticationManager authenticationManager;
    private final PasswordEncoder passwordEncoder;

    // ── REGISTER ─────────────────────────────────────────────────
    @Transactional
    public AuthDto.TokenResponse register(AuthDto.RegisterRequest request) {
        log.info("Registration attempt: {}", request.getEmail());

        if (userRepository.existsByEmail(request.getEmail())) {
            throw new AppExceptions.DuplicateResource("Email already registered: " + request.getEmail());
        }

        User user = User.builder()
                .email(request.getEmail())
                .name(request.getName())
                /*
                 * WHY encode the password here?
                 * We NEVER store plain text. BCrypt produces a different hash
                 * every call (due to random salt) — even the same password
                 * produces a unique hash each time. One-way, not reversible.
                 */
                .password(passwordEncoder.encode(request.getPassword()))
                .provider(AuthProvider.LOCAL).providerId(null)
                .role("ROLE_USER")
                .active(true)
                .build();

        userRepository.save(user);
        log.info("User registered: {}", user.getEmail());

        return buildTokenResponse(user);
    }

    // ── LOGIN ────────────────────────────────────────────────────
    @Transactional
    public AuthDto.TokenResponse login(AuthDto.LoginRequest request) {
        log.info("Login attempt for :{}", request.getEmail());
        // Load the user first so we can check if they're an OAuth2 user
        User user = userRepository.findByEmail(request.getEmail())
                .orElseThrow(() ->
                        new AppExceptions.InvalidCredentialException("Invalid email or password")
                );
        /*
         * WHY guard against OAuth2 users attempting local login?
         * OAuth2 users (Google/GitHub) have no password in our DB (null).
         * If we let them reach AuthenticationManager, the password comparison
         * would fail silently or produce confusing errors.
         * We catch this early and return a helpful (but not too revealing) message.
         *
         * In a real app you might say: "This email is registered via Google.
         * Please use 'Login with Google' instead."
         */
        if (user.getProvider() != AuthProvider.LOCAL) {
            throw new AppExceptions.InvalidCredentialException(
                    "This account used for " + user.getProvider() + "login. " +
                            "Please used the social login button."
            );
        }
        try {
            /*
             * WHY UsernamePasswordAuthenticationToken (2-arg)?
             * The 2-argument constructor creates an UNAUTHENTICATED token.
             * We hand it to AuthenticationManager which:
             *   1. Calls loadUserByUsername(email) → loads UserDetails from DB
             *   2. Calls passwordEncoder.matches(rawPassword, storedHash)
             *   3. If match → returns an AUTHENTICATED token (3-arg)
             *   4. If no match → throws BadCredentialsException
             *
             * We don't do the password comparison ourselves — we delegate
             * to Spring Security's DaoAuthenticationProvider. This ensures
             * all Spring Security checks (account locked, expired, etc.) run.
             */
            authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            request.getEmail(),
                            request.getPassword()
                    )
            );
        } catch (BadCredentialsException ex) {
            log.info("Failed to attempt for: {}", ex.getMessage());
            throw new AppExceptions.InvalidCredentialException("Invalid email or password");
        }
        log.info("Login successful: {}", request.getEmail());
        return buildTokenResponse(user);
    }

    // ── REFRESH TOKEN ────────────────────────────────────────────
    /*
     * WHY @Transactional?
     * Token rotation: delete old refresh token + create new one.
     * Both must succeed or both roll back. Atomicity is critical here.
     * A partial success (old deleted but new not created) would lock
     * the user out with no way to get a new access token.
     */
    @Transactional
    public AuthDto.TokenResponse refresh(String request) {
        log.debug("Token refresh request received.");
        // Step 1: Find + validate the refresh token in DB
        RefreshToken refreshToken = refreshTokenService.findAndValidate(request);

        // Step 2: Get the associated user
        User user = refreshToken.getUser();

        if (!user.isActive()) {
            refreshTokenService.deleteByUser(user);
            throw new AppExceptions.InvalidTokenRefreshException("Account has been deactivated. Please contact support.");
        }

        // Step 3: Rotate refresh token (delete old, create new)
        RefreshToken newRefreshToken = refreshTokenService.rotateRefreshToken(refreshToken);

        // Step 4: Issue a new access token (JWT)
        UserDetails userDetails = buildUserDetails(user);
        String accessToken = jwtService.generateAccessToken(userDetails);

        log.info("Token refreshed for user :{}", user.getEmail());

        return AuthDto.TokenResponse.builder()
                .accessToken(accessToken)
                .refreshToken(newRefreshToken.getToken())
                .tokenType("Bearer")
                .accessTokenExpireIn(jwtService.getAccessTokenExpiryMs())
                .email(user.getEmail())
                .role(user.getRole())
                .provider(user.getProvider().name())
                .build();
    }

    // ── LOGOUT ───────────────────────────────────────────────────
    /*
     * WHY does logout take the email from SecurityContext (not from request body)?
     * The user is authenticated — their email is already in the SecurityContext
     * from the JwtAuthenticationFilter. We use it to find and delete their
     * refresh token. No need to trust client-provided email in the body.
     *
     * Logout works for BOTH local and OAuth2 users — the refresh token
     * in DB is the same regardless of how the user originally signed in.
     */
    @Transactional
    public void logout(String email) {
        log.info("Logout request for: {}", email);

        userRepository.findByEmail(email).ifPresent(
                user -> {
                    refreshTokenService.deleteByUser(user);
                    log.info("Refresh token deleted, user logged out: {}", email);
                }
        );

        /*
         * NOTE on access token invalidation:
         * The access token (JWT) remains technically valid for up to 15 minutes.
         * For immediate full invalidation, add the token's jti (JWT ID) claim
         * to a Redis denylist and check it in JwtAuthenticationFilter.
         * For this project, 15-minute expiry is an acceptable tradeoff.
         */
    }


    // ── PRIVATE HELPERS ──────────────────────────────────────────

    private AuthDto.TokenResponse buildTokenResponse(User user) {
        UserDetails userDetails = buildUserDetails(user);
        RefreshToken refreshToken = refreshTokenService.createRefreshToken(user);
        String accessToken = jwtService.generateAccessToken(userDetails);

        return AuthDto.TokenResponse.builder()
                .accessToken(accessToken)
                .refreshToken(refreshToken.getToken())
                .tokenType("Bearer")
                .accessTokenExpireIn(jwtService.getAccessTokenExpiryMs())
                .email(user.getEmail())
                .role(user.getRole())
                .provider(user.getProvider().name())
                .build();
    }

    private UserDetails buildUserDetails(User user) {
        return new org.springframework.security.core.userdetails.User(
                user.getEmail(),
                user.getPassword() != null ? user.getPassword() : "",
                List.of(new SimpleGrantedAuthority(user.getRole()))
        );
    }


}
