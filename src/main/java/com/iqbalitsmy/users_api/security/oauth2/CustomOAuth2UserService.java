package com.iqbalitsmy.users_api.security.oauth2;

import com.iqbalitsmy.users_api.exception.AppExceptions;
import com.iqbalitsmy.users_api.model.AuthProvider;
import com.iqbalitsmy.users_api.model.User;
import com.iqbalitsmy.users_api.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * ================================================================
 * STEP 9: CUSTOM OAUTH2 USER SERVICE
 * ================================================================
 *
 * WHY extend DefaultOAuth2UserService?
 * DefaultOAuth2UserService is Spring Security's built-in service that:
 *   1. Takes the OAuth2 access token (received after the user approves)
 *   2. Calls the provider's UserInfo endpoint (Google's /userinfo, GitHub's /user)
 *   3. Returns an OAuth2User with the provider's attributes
 *
 * We extend it to add OUR logic AFTER step 3:
 *   4. Extract the user's info using our OAuth2UserInfoFactory
 *   5. Find or create a User in OUR database
 *   6. Return an OAuth2User (Spring Security's type) that represents this user
 *
 * WHY is this called automatically?
 * Spring Security's OAuth2 auto-configuration wires this class in because:
 *   a) It's annotated @Service (Spring detects it)
 *   b) It extends DefaultOAuth2UserService (Spring knows what it's for)
 *   c) SecurityConfig registers it via .userInfoEndpoint(u -> u.userService(this))
 *
 * ── THE FULL OAUTH2 FLOW (high level) ────────────────────────────
 *
 *  1. User clicks "Login with Google"
 *  2. Client calls GET /oauth2/authorization/google
 *  3. Spring redirects user to Google's consent screen
 *  4. User approves → Google redirects to /login/oauth2/code/google?code=XYZ
 *  5. Spring exchanges the code for an access token (server-to-server)
 *  6. Spring calls THIS service with the access token
 *  7. We call Google's /userinfo endpoint → get user attributes
 *  8. We find or create the user in our DB
 *  9. Control passes to OAuth2AuthenticationSuccessHandler
 * 10. We issue our JWT and redirect to the frontend
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class CustomOAuth2UserService extends DefaultOAuth2UserService {
    private final UserRepository userRepository;
    /*
     * WHY override loadUser()?
     * This is the SINGLE method we must override.
     * Spring Security calls it after exchanging the authorization code
     * for an access token and fetching the user's profile from the provider.
     *
     * @param userRequest  → contains: registrationId ("google"/"github"),
     *                       accessToken, and client registration details
     * @return OAuth2User  → Spring Security's representation of the OAuth2 user
     */
    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        OAuth2User oAuth2User = super.loadUser(userRequest);
        // Step 1: Call parent → fetches attributes from Google/GitHub's userinfo endpoint
        try {
            return processOAuth2User(userRequest, oAuth2User);
        } catch (AppExceptions.OAuth2AuthenticationException ex) {
            /*
             * WHY rethrow as OAuth2AuthenticationException (Spring's type)?
             * Spring Security's OAuth2 infrastructure only catches its OWN
             * OAuth2AuthenticationException. If we throw our custom exception,
             * Spring won't handle it gracefully — it'll become a 500 error.
             * We wrap ours in Spring's so the failure handler is triggered correctly.
             */
            throw new OAuth2AuthenticationException(ex.getMessage());
        }
    }

    private OAuth2User processOAuth2User(OAuth2UserRequest userRequest, OAuth2User oAuth2User) {
        // Which provider is this? "google" or "github"
        String registrationId = userRequest.getClientRegistration().getRegistrationId();
        log.debug("processing OAuth2 user from provider: {}", registrationId);
        // Step 2: Use the factory to normalise provider-specific attributes
        OAuth2UserInfo userInfo = OAuth2UserInfoFactory.getOAuth2UserInfo(registrationId, oAuth2User.getAttributes());

        /*
         * WHY validate email?
         * Some providers (GitHub with private email) may not provide an email.
         * Our User entity uses email as the login identifier.
         * We cannot create/find a user without one.
         */
        if (userInfo.getEmail() == null || userInfo.getEmail().isBlank()) {
            throw new AppExceptions.OAuth2AuthenticationException("Email not provided by " + registrationId + ". Please make your email public in your " + registrationId + "settings.");
        }
        // Convert "google" → AuthProvider.GOOGLE
        AuthProvider provider = AuthProvider.valueOf(registrationId.toUpperCase());
        // Step 3: Find existing user or create a new one
        User user = findOrCreateUser(userInfo, provider);
        /*
         * WHY return DefaultOAuth2User?
         * Spring Security's filter chain expects an OAuth2User back.
         * DefaultOAuth2User wraps the attributes and authorities.
         *
         * WHY "email" as the nameAttributeKey?
         * This tells Spring Security which attribute in the map is the
         * "principal name" (the unique identifier for this user in Spring's context).
         * We add "email" to the attributes map so it's always available,
         * regardless of whether the provider uses "email" or "sub" as their key.
         *
         * The OAuth2AuthenticationSuccessHandler will read this
         * to find the user and issue our JWT.
         */
        Map<String, Object> attributes = new HashMap<>(oAuth2User.getAttributes());
        // normalise — always present as "email"
        attributes.put("email", userInfo.getEmail());

        return new DefaultOAuth2User(
                List.of(new SimpleGrantedAuthority(user.getRole())),
                attributes,
                "email" // nameAttributeKey → OAuth2User.getName() returns the email
        );
    }
    /*
     * WHY findOrCreateUser()?
     * This is the HEART of the OAuth2 integration. Two scenarios:
     *
     * Scenario A — RETURNING USER (they've logged in with this provider before):
     *   - Find by (provider, providerId) → update their name/picture (may have changed)
     *   - return the existing user
     *
     * Scenario B — NEW USER (first time logging in with this provider):
     *   - Check if their email exists from a LOCAL account
     *     → If yes: link accounts (update LOCAL user to this provider)
     *     → If no:  create a brand new user
     *
     * INTERVIEW TIP — "How do you handle account linking?"
     * If user@gmail.com exists as a LOCAL account (registered with password)
     * and then they click "Login with Google" using the same email,
     * we link the accounts by updating their provider to GOOGLE.
     * They can no longer log in with password (or you can support both).
     * For this project we link silently; in production ask the user to confirm.
     */
    private User findOrCreateUser(OAuth2UserInfo userInfo, AuthProvider provider) {
        // Case 1: Returning OAuth2 user — find by provider + their ID at that provider
        Optional<User> existingOAuth2User = userRepository.findByProviderAndProviderId(provider, userInfo.getId());

        // Case 1: Returning OAuth2 user — find by provider + their ID at that provider
        if (existingOAuth2User.isPresent()) {
            User user = existingOAuth2User.get();
            log.info("Returning OAuth2 user: {} via {}", user.getEmail(), provider);
        // Update profile (name/picture may have changed at the provider)
            user.setName(userInfo.getName());
            user.setImageUrl(userInfo.getImageUrl());
            return userRepository.save(user);
        }
        // Case 2: Email exists as LOCAL account — link to this OAuth2 provider
        Optional<User> existingLocalUser = userRepository.findByEmail(userInfo.getEmail());

        if (existingLocalUser.isPresent()) {
            User user = existingLocalUser.get();
            log.info("Linking LOCAL account {} to provider {}", user.getEmail(), provider);

            user.setProvider(provider);
            user.setProviderId(userInfo.getId());
            user.setImageUrl(userInfo.getImageUrl());
            user.setEmailVerified(true);

            return userRepository.save(user);
        }

        // Case 3: Brand-new user — create account from OAuth2 profile
        log.info("Creating new user from OAuth2 provider {}:{}", provider, userInfo.getEmail());
        User newUser = User.builder().email(userInfo.getEmail()).name(userInfo.getName()).imageUrl(userInfo.getImageUrl()).password(null).emailVerified(true).provider(provider).providerId(userInfo.getId()).role("ROLE_USER").active(true).build();

        return userRepository.save(newUser);
    }

}
