package com.iqbalitsmy.users_api.service;

import com.iqbalitsmy.users_api.Dto.AuthDto;
import com.iqbalitsmy.users_api.exception.AppExceptions;
import com.iqbalitsmy.users_api.model.AuthProvider;
import com.iqbalitsmy.users_api.model.RefreshToken;
import com.iqbalitsmy.users_api.model.User;
import com.iqbalitsmy.users_api.repository.UserRepository;
import com.iqbalitsmy.users_api.security.jwt.JwtService;
import com.iqbalitsmy.users_api.security.oauth2.RefreshTokenService;
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

/*
 *  OAUTH2 PATH:
 *    GET /oauth2/authorization/{provider} → redirect to Google/GitHub
 *    GET /login/oauth2/code/{provider}    → Spring handles code exchange
 *    CustomOAuth2UserService              → find/create user in DB
 *    OAuth2SuccessHandler                 → issue JWT + redirect to frontend
 *    POST /auth/refresh                   → SAME as local (shared endpoint!)
 *    POST /auth/logout                    → SAME as local (shared endpoint!)
 * */

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
        User user = userRepository.findByEmail(request.getEmail())
                .orElseThrow(() ->
                        new AppExceptions.InvalidCredentialException("Invalid email or password")
                );
        if (user.getProvider() != AuthProvider.LOCAL) {
            throw new AppExceptions.InvalidCredentialException(
                    "This account used for " + user.getProvider() + "login. " +
                            "Please used the social login button."
            );
        }
        try {
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
    @Transactional
    public AuthDto.TokenResponse refresh(AuthDto.RefreshRequest request) {
        log.debug("Token refresh request received.");
        // Step 1: Find + validate the refresh token in DB
        RefreshToken refreshToken = refreshTokenService.findAndValidate(request.getRefreshToken());

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
                .refreshToken(refreshToken.getToken())
                .tokenType("Bearer")
                .accessTokenExpireIn(jwtService.getAccessTokenExpiryMs())
                .email(user.getEmail())
                .role(user.getRole())
                .provider(user.getProvider().name())
                .build();
    }

    // ── LOGOUT ───────────────────────────────────────────────────
    @Transactional
    public void logout(String email) {
        log.info("Logout request for: {}", email);

        userRepository.findByEmail(email).ifPresent(
                user -> {
                    refreshTokenService.deleteByUser(user);
                    log.info("Refresh token deleted, user logged out: {}", email);
                }
        );
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
