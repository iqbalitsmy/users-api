package com.iqbalitsmy.users_api.config;

import com.iqbalitsmy.users_api.security.CustomUserDetailsService;
import com.iqbalitsmy.users_api.security.jwt.JwtAuthenticationFilter;
import com.iqbalitsmy.users_api.security.oauth2.CustomOAuth2UserService;
import com.iqbalitsmy.users_api.security.oauth2.OAuth2AuthenticationFailerHandler;
import com.iqbalitsmy.users_api.security.oauth2.OAuth2AuthenticationSuccessHandler;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
/**
 * ================================================================
 * STEP 15: SECURITY CONFIGURATION — The Wiring Hub
 * ================================================================
 *
 * WHY @Configuration + @EnableWebSecurity?
 * @Configuration  → this class declares Spring beans via @Bean methods
 * @EnableWebSecurity → activates Spring Security's web filter chain.
 *                     Without it, security is auto-configured but not customisable.
 *
 * WHY @EnableMethodSecurity?
 * Enables @PreAuthorize("hasRole('ADMIN')") on individual methods.
 * Two-layer security: URL rules (here) + method rules (@PreAuthorize).
 * Defense in depth — if one layer is misconfigured, the other catches it.
 *
 * ── THE BIG PICTURE: TWO AUTH FLOWS IN ONE CONFIG ────────────────
 *
 *  FLOW A: Local JWT Auth
 *    POST /auth/register → open
 *    POST /auth/login    → open
 *    POST /auth/refresh  → open (token itself is the credential)
 *    POST /auth/logout   → requires valid JWT
 *    GET  /api/**        → requires valid JWT
 *
 *    Filter chain:
 *    Request → [JwtAuthenticationFilter] → [AuthorizationFilter] → Controller
 *
 *  FLOW B: OAuth2 Social Login
 *    GET /oauth2/authorization/google → Spring redirects to Google
 *    GET /login/oauth2/code/google   → Spring handles code exchange
 *                                      → CustomOAuth2UserService processes user
 *                                      → OAuth2SuccessHandler issues JWT
 *                                      → Redirect to frontend with token
 *
 *    Filter chain:
 *    Request → [OAuth2AuthorizationRequestRedirectFilter]
 *            → [OAuth2LoginAuthenticationFilter]
 *            → CustomOAuth2UserService
 *            → OAuth2AuthenticationSuccessHandler
 *
 * Both flows END with a JWT — after that, all subsequent API calls
 * are identical regardless of how the user originally authenticated.
 *
 * INTERVIEW TIP — "Why is SecurityFilterChain a bean now instead of
 * extending WebSecurityConfigurerAdapter?"
 * WebSecurityConfigurerAdapter was deprecated in Spring Security 5.7
 * and removed in Spring Boot 3. The bean-based approach is more
 * composable (multiple chains possible), easier to test, and follows
 * modern Spring conventions.
 */
@Configuration
@EnableWebSecurity
@EnableMethodSecurity
@RequiredArgsConstructor
public class SecurityConfig {
    private final CustomUserDetailsService userDetailsService;
    private final CustomOAuth2UserService customOAuth2UserService;
    private final JwtAuthenticationFilter jwtAuthenticationFilter;
    private final OAuth2AuthenticationSuccessHandler oAuth2SuccessHandler;
    private final OAuth2AuthenticationFailerHandler oAuth2FailerHandler;

    // ── BEAN 1: PasswordEncoder ───────────────────────────────────
    /*
     * WHY BCryptPasswordEncoder?
     * Designed specifically for password hashing:
     *  - One-way (cannot reverse)
     *  - Random salt per hash (same input → different hash each time)
     *  - Intentionally slow (configurable work factor, default 10 rounds)
     *  - Industry standard — used by banks, SaaS, etc.
     * NEVER use MD5/SHA for passwords — they're designed to be FAST (brute-forceable).
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    // ── BEAN 2: AuthenticationProvider ───────────────────────────
    /*
     * WHY DaoAuthenticationProvider?
     * Wires together our UserDetailsService + PasswordEncoder
     * into a provider that AuthenticationManager can use.
     *
     * When AuthenticationManager.authenticate(token) is called:
     *   1. DaoAuthenticationProvider calls userDetailsService.loadUserByUsername()
     *   2. Gets the stored BCrypt hash
     *   3. Calls passwordEncoder.matches(rawInput, storedHash)
     *   4. Match → authenticated; no match → BadCredentialsException
     *
     * This only applies to LOCAL login. OAuth2 login bypasses this entirely.
     */
    @Bean
    public AuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider(userDetailsService);
        provider.setPasswordEncoder(passwordEncoder());
        return provider;
    }

    // ── BEAN 3: AuthenticationManager ────────────────────────────
    /*
     * WHY expose as a bean?
     * AuthService.login() calls authManager.authenticate(...).
     * Spring Boot 3 doesn't auto-expose it — we must declare it explicitly.
     * AuthenticationConfiguration provides the pre-configured manager
     * that knows about our DaoAuthenticationProvider.
     */
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) {
        return config.getAuthenticationManager();
    }
    // ── BEAN 4: SecurityFilterChain — MAIN CONFIG ─────────────────
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                /*
                 * WHY disable CSRF?
                 * CSRF attacks exploit browser cookie auto-send behaviour.
                 * Our API uses JWT in the Authorization header — browsers don't
                 * auto-send headers, so CSRF is not a threat for this API.
                 * Keeping CSRF enabled would require a CSRF token on every
                 * POST/PUT/DELETE — unnecessary complexity for a REST API.
                 *
                 * EXCEPTION: If you serve the OAuth2 redirect to a web browser
                 * and use cookies for token storage, you SHOULD re-enable CSRF.
                 * For JWT in Authorization headers, it's safe to disable.
                 */
                .csrf(csrf -> csrf.disable())
                /*
                 * WHY STATELESS?
                 * REST APIs must be stateless — no HttpSession on the server.
                 * Each request carries its own authentication (JWT).
                 *
                 * IMPORTANT EXCEPTION: The OAuth2 flow temporarily needs session state.
                 * Spring Security stores the OAuth2 "state" parameter in session to
                 * prevent CSRF during the authorization code flow. We set STATELESS
                 * globally, which means Spring Security will use a NullSessionStrategy
                 * for OAuth2 too — this works because the state validation is handled
                 * in the redirect URI parameters, not a session cookie.
                 *
                 * For stricter setups, use IF_REQUIRED during OAuth2 and STATELESS elsewhere.
                 */
                .sessionManagement(
                        session ->
                                session.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                )
                // ── URL AUTHORIZATION RULES ───────────────────────────
                /*
                 * IMPORTANT: Rules are evaluated TOP TO BOTTOM, FIRST MATCH WINS.
                 * Put more specific rules above more general ones.
                 *
                 * WHY permit /auth/**?
                 * Login and register must be public — you can't send a JWT to get a JWT.
                 * Refresh must be public — its credential IS the refresh token in the body.
                 *
                 * WHY permit /oauth2/** and /login/oauth2/**?
                 * /oauth2/authorization/{provider} → initiate the OAuth2 redirect
                 * /login/oauth2/code/{provider}    → receive the authorization code callback
                 * Both are part of the OAuth2 handshake — must be accessible without a JWT.
                 *
                 * WHY permit /h2-console/**?
                 * Development tool. Remove this in production.
                 */
                .authorizeHttpRequests(
                        auth ->
                                auth
                                        .requestMatchers("/auth/success").permitAll()
                                        .requestMatchers("/auth/**").permitAll()
                                        .requestMatchers("/oauth2/**").permitAll()
                                        .requestMatchers("/login/oauth2/**").permitAll()
                                        .requestMatchers("/h2-console/**").permitAll()
                                        .requestMatchers(HttpMethod.GET,"/api/users/all").hasRole("ADMIN")
                                        .requestMatchers(HttpMethod.DELETE,"/api/users/**").hasRole("ADMIN")
                                        .anyRequest().authenticated()
                )
                // ── OAUTH2 LOGIN CONFIGURATION ────────────────────────
                /*
                 * WHY .oauth2Login()?
                 * This activates ALL the OAuth2 client machinery:
                 *  - Registers /oauth2/authorization/{registrationId} endpoint
                 *    (where the OAuth2 redirect flow begins)
                 *  - Registers /login/oauth2/code/{registrationId} callback endpoint
                 *    (where Google/GitHub redirects back with the authorization code)
                 *  - Handles the code-for-token exchange (server-to-server call)
                 *  - Calls our CustomOAuth2UserService to process the user
                 *  - Calls our success/failure handlers
                 *
                 * WHY userInfoEndpoint + userService?
                 * Wires in our CustomOAuth2UserService so Spring calls it
                 * (instead of the default) after fetching the user's profile
                 * from the provider.
                 *
                 * WHY successHandler + failureHandler?
                 * After OAuth2 processing, control goes to these handlers:
                 *  Success → issue our JWT + redirect to frontend
                 *  Failure → redirect to frontend with error message
                 */
                .oauth2Login(
                        oauth2 ->
                                oauth2
                                        .userInfoEndpoint(
                                                userInfo ->
                                                        userInfo.userService(customOAuth2UserService)
                                        )
                                        .successHandler(oAuth2SuccessHandler)
                                        .failureHandler(oAuth2FailerHandler)
                )
                // ── JWT FILTER ────────────────────────────────────────
                /*
                 * WHY addFilterBefore(jwt, UsernamePasswordAuthFilter)?
                 * Insert our JWT filter BEFORE Spring's default username/password filter.
                 * This ensures JWT authentication is checked first on every request.
                 * If a valid JWT is present, the SecurityContext is set before any
                 * other filter or controller sees the request.
                 */
                .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
                .authenticationProvider(authenticationProvider())
                // ── H2 CONSOLE FIX ────────────────────────────────────
                // H2 console uses iFrames — allow same-origin iframes for dev
                .headers(
                        headers ->
                                headers.frameOptions(frame -> frame.sameOrigin())
                );
        return http.build();
    }


}
