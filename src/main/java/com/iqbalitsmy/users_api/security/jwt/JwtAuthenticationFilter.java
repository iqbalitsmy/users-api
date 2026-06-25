package com.iqbalitsmy.users_api.security.jwt;

import com.iqbalitsmy.users_api.exception.AppExceptions;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
/**
 * ================================================================
 * STEP 7: JWT AUTHENTICATION FILTER
 * ================================================================
 *
 * WHY extend OncePerRequestFilter?
 * Guarantees this filter executes EXACTLY ONCE per HTTP request.
 * Servlet forwarding/dispatching can cause filters to run multiple times.
 * OncePerRequestFilter uses a request attribute to prevent re-execution.
 *
 * ── WHERE THIS FILTER SITS ───────────────────────────────────────
 *
 *  Incoming Request
 *       ↓
 *  [JwtAuthenticationFilter]    ← our filter — reads Bearer token
 *       ↓ sets SecurityContext
 *  [OAuth2 filters]             ← Spring's OAuth2 filters (if applicable)
 *       ↓
 *  [AuthorizationFilter]        ← Spring checks roles from SecurityContext
 *       ↓
 *  [Controller method]
 *
 * ── TWO AUTH PATHS IN THIS APPLICATION ───────────────────────────
 *
 *  Path A — Local login / OAuth2 login already completed:
 *    Client has a JWT → this filter validates it → sets SecurityContext
 *
 *  Path B — Initiating OAuth2 login:
 *    Client hits GET /oauth2/authorization/google
 *    No JWT yet → this filter does nothing (no Authorization header)
 *    Spring's OAuth2 filters handle the redirect to Google
 *
 * This filter only acts on requests that carry a Bearer token.
 * Requests without one pass through untouched.
 */

@Component
@RequiredArgsConstructor
@Slf4j
public class JwtAuthenticationFilter extends OncePerRequestFilter {
    private final JwtService jwtService;
    private final UserDetailsService userDetailsService;

    // ── SKIP JWT CHECK FOR THESE PATHS ───────────────────────────
    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        String path = request.getServletPath();
        return path.equals("/auth/login")
                || path.equals("/auth/register")
                || path.startsWith("/oauth2/")
                || path.startsWith("/login/oauth2/");
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        // ── STEP A: Extract Authorization header ──────────────────
        String authHeader = request.getHeader("Authorization");

        /*
         * WHY pass through if no Bearer token?
         * Not every request needs JWT auth:
         *  - POST /auth/login, POST /auth/register  → public, no token
         *  - GET /oauth2/authorization/google       → initiates OAuth2 flow
         * If no "Bearer " header is present, this filter steps aside.
         * Spring Security's AuthorizationFilter will handle the 401 if needed.
         */
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return;
        }
        // ── STEP B: Strip "Bearer " prefix → raw JWT ──────────────
        String jwt = authHeader.substring(7);
        // ── STEP C: Extract email from JWT ────────────────────────
        String userEmail;
        try {
            userEmail = jwtService.extractEmail(jwt);
        } catch (AppExceptions.InvalidTokenException ex) {
            log.warn("Invalid jwt in request to {}: {}", request.getRequestURI(), ex.getMessage());
//            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, ex.getMessage());
            filterChain.doFilter(request, response);  // let it through unauthenticated
            return;
        }

        // ── STEP D: Authenticate if not already done ──────────────
        /*
         * WHY check SecurityContext is empty?
         * Another filter or previous step may have already authenticated
         * this request. We never overwrite an existing authentication.
         * This prevents double-processing and potential security issues.
         */
        if (userEmail != null && SecurityContextHolder.getContext().getAuthentication() == null) {
            UserDetails userDetails = userDetailsService.loadUserByUsername(userEmail);

            if (jwtService.isTokenValid(jwt, userDetails)) {
                /*
                 * WHY 3-argument UsernamePasswordAuthenticationToken?
                 * 2-arg = UNAUTHENTICATED token (credentials not yet verified)
                 * 3-arg = AUTHENTICATED token (credentials already verified)
                 *
                 * We pass null for credentials (the password/token itself).
                 * At this point, the JWT signature IS the proof of identity.
                 * Storing the raw token in credentials would be a memory leak risk.
                 */
                UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
                // Attach request metadata (IP, session ID) for auditing
                authenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

                /*
                 * WHY SecurityContextHolder.getContext().setAuthentication()?
                 * THIS is the key step. Spring Security reads this context
                 * to decide if the request is authenticated and what roles it has.
                 *
                 * ThreadLocal: each request thread has its own SecurityContext.
                 * It is cleared automatically after the request completes.
                 * Never bleeds between requests (thread safety is built in).
                 */
                SecurityContextHolder.getContext().setAuthentication(authenticationToken);

                log.debug("JWT authenticated user: {} for URI: {}", userDetails.getUsername(), request.getRequestURI());
            }
        }
        // ── STEP E: Continue filter chain regardless ───────────────
        filterChain.doFilter(request, response);
    }

}
