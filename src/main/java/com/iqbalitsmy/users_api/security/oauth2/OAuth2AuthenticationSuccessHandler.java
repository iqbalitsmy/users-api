package com.iqbalitsmy.users_api.security.oauth2;

import com.iqbalitsmy.users_api.exception.AppExceptions;
import com.iqbalitsmy.users_api.model.User;
import com.iqbalitsmy.users_api.repository.UserRepository;
import com.iqbalitsmy.users_api.security.jwt.JwtService;
import com.iqbalitsmy.users_api.service.RefreshTokenService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.IOException;
import java.util.List;
/**
 * ================================================================
 * STEP 10a: OAUTH2 AUTHENTICATION SUCCESS HANDLER
 * ================================================================
 *
 * WHY a custom success handler?
 * After CustomOAuth2UserService processes the user, Spring Security's
 * default success handler redirects to "/" or the last page visited.
 * That's for server-rendered apps. For REST APIs, we need to:
 *   1. Issue our own JWT (access + refresh tokens)
 *   2. Redirect the user's BROWSER to the frontend app
 *      with the token embedded in the URL query parameters
 *
 * WHY redirect WITH the token in the URL?
 * The OAuth2 flow is browser-based (redirect dance).
 * The final step is a redirect — we can't return JSON here.
 * The frontend (React/Vue) extracts the token from the URL,
 * stores it in memory/localStorage, and uses it for API calls.
 *
 * WHY extend SimpleUrlAuthenticationSuccessHandler?
 * It provides the sendRedirect() infrastructure.
 * We just override onAuthenticationSuccess() to build the redirect URL
 * with our JWT appended.
 *
 * ── THE BRIDGE: OAuth2 → JWT ─────────────────────────────────────
 *
 * This handler is the critical bridge between the two auth systems:
 *
 *   [OAuth2 world]                        [JWT world]
 *   Google authenticates user        →    We issue our own JWT
 *   OAuth2User in SecurityContext    →    Bearer token in HTTP header
 *   Browser-based redirect flow      →    Stateless REST API calls
 *
 * After this handler runs, the OAuth2 session is done.
 * Everything from here is standard JWT.
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class OAuth2AuthenticationSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    private final JwtService jwtService;
    private final RefreshTokenService refreshTokenService;
    private final UserRepository userRepository;

    @Value("${app.auth2.redirect-uri}")
    private String redirectUri;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                        Authentication authentication) throws IOException {
        /*
         * WHY cast to OAuth2User?
         * After the OAuth2 flow, the Authentication principal is an OAuth2User.
         * We need to extract the email to find the user in our DB.
         *
         * Remember: in CustomOAuth2UserService we always put "email"
         * into the attributes map as a normalised key. So this always works.
         */
        OAuth2User oAuth2User = (OAuth2User) authentication.getPrincipal();
        String email = oAuth2User.getAttribute("email");
        log.info("OAuth2 login success for: {}", email);

        // Load our User entity from DB (we need it to build UserDetails for JWT)
        User user = userRepository.findByEmail(email).orElseThrow(() -> new AppExceptions.ResourceNotFoundException("User not found OAuth2 login :" + email));

        /*
         * WHY build UserDetails manually here?
         * JwtService.generateAccessToken() takes a UserDetails object.
         * We construct it directly rather than going through UserDetailsService
         * (which would be an extra DB round-trip when we already have the User).
         */
        UserDetails userDetails = new org.springframework.security.core.userdetails.User(
                user.getEmail(),
                user.getPassword() != null ? user.getPassword() : "",
                List.of(new SimpleGrantedAuthority(user.getRole()))
        );
        // Issue access token (JWT) + refresh token (stored in DB)
        String accessToken = jwtService.generateAccessToken(userDetails);
        String refreshToken = refreshTokenService.createRefreshToken(user).getToken();
        /*
         * WHY redirect with tokens in query params?
         * This is the standard "OAuth2 + SPA" pattern.
         * The browser is redirected to the frontend app.
         * The frontend reads the tokens from the URL, stores them, and strips the URL.
         *
         * Example redirect URL:
         *   http://localhost:3000/oauth2/callback
         *     ?accessToken=eyJhbGci...
         *     &refreshToken=abc123def456
         *
         * WHY UriComponentsBuilder?
         * Safely appends query parameters — handles URL encoding automatically.
         * No risk of injection via special characters in token values.
         *
         * SECURITY NOTE: In production, prefer httpOnly cookies over URL params
         * for token delivery (tokens in URLs appear in browser history and logs).
         * URL params are fine for learning and development.
         */
        String targetUrl = UriComponentsBuilder.fromUriString(redirectUri)
                .queryParam("accessToken", accessToken)
                .queryParam("refreshToken", refreshToken)
                .build().toUriString();

        /*
         * WHY clearAuthenticationAttributes()?
         * Cleans up the temporary OAuth2 state stored in the session
         * (SPRING_SECURITY_SAVED_REQUEST, etc.).
         * We're going stateless from this point — no need for session data.
         */
        clearAuthenticationAttributes(request);

        getRedirectStrategy().sendRedirect(request, response, targetUrl);
    }
}
