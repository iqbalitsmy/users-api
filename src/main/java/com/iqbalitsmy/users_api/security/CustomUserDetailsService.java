package com.iqbalitsmy.users_api.security;

import com.iqbalitsmy.users_api.model.User;
import com.iqbalitsmy.users_api.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.List;
/**
 * ================================================================
 * STEP 11: CUSTOM USER DETAILS SERVICE
 * ================================================================
 *
 * WHY do we still need this with OAuth2?
 * This service is called in TWO different places:
 *
 *  1. LOCAL LOGIN — AuthenticationManager.authenticate() calls this
 *     during POST /auth/login to load the user from DB, then
 *     DaoAuthenticationProvider compares the submitted password
 *     with the stored BCrypt hash.
 *
 *  2. JWT FILTER — JwtAuthenticationFilter calls this on EVERY
 *     protected request to reload the user's current state from DB.
 *     This is the "kill switch": if a user is deactivated, their
 *     JWT stops working immediately even before it expires.
 *
 * WHY NOT called during OAuth2 login?
 * OAuth2 login is handled entirely by CustomOAuth2UserService.
 * That service talks directly to the UserRepository without going
 * through UserDetailsService. The two flows are independent.
 *
 * INTERVIEW TIP — "Can an OAuth2 user call a local login?"
 * No. If provider = GOOGLE and password = null, AuthService.login()
 * detects this and throws InvalidCredentialsException before even
 * reaching AuthenticationManager. We guard that in the service layer.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class CustomUserDetailsService implements UserDetailsService {
    private final UserRepository userRepository;
    /*
     * WHY override loadUserByUsername?
     * This is the single method of UserDetailsService.
     * Spring Security calls this to fetch user data for authentication.
     * We use email as the "username" throughout this application.
     *
     * @param username — the email address from the JWT subject claim
     *                   or from the login request body
     */
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        /*
         * WHY validate format before hitting the DB?
         * This method is called on every protected request via the JWT filter.
         * Rejecting malformed emails here saves a DB round-trip.
         * Also guards against injection-style inputs.
         */
        if (username == null || username.isBlank()){
            log.warn("Invalid email in loadUserByUsername");
            throw new UsernameNotFoundException("Invalid Credential");
        }

        User user = userRepository.findByEmail(username)
                .orElseThrow(() -> {
                    log.warn("User not found for: {}",username);
                    /*
                     * WHY "Invalid credentials" instead of "User not found"?
                     * Security best practice: vague error messages.
                     * If we reveal "user not found", attackers can enumerate
                     * which email addresses are registered in our system.
                     * Always return the same generic message for all auth failures.
                     */
                    return new UsernameNotFoundException("Invalid credential");
                });
        if (!user.isActive()){
            log.warn("Deactivated user attempt to access: {}",user.getEmail());
            throw new UsernameNotFoundException("Invalid credential");
        }

        /*
         * WHY return Spring's User class (not our User entity)?
         * Spring Security works with UserDetails — its own interface.
         * We map our domain User → Spring's UserDetails implementation here.
         *
         * WHY empty string for password when null?
         * OAuth2 users have no password (null in DB).
         * Spring's User constructor rejects null passwords.
         * Empty string is safe — DaoAuthenticationProvider will reject
         * any password comparison against an empty string anyway.
         * OAuth2 users never reach this code path for login (guarded in AuthService).
         */
        return new org.springframework.security.core.userdetails.User(
                user.getEmail(),
                user.getPassword() != null ? user.getPassword() : "",
                List.of(new SimpleGrantedAuthority(user.getRole()))
        );
    }
}
