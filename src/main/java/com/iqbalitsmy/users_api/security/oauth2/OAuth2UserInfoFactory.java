package com.iqbalitsmy.users_api.security.oauth2;

import com.iqbalitsmy.users_api.exception.AppExceptions;

import java.util.Map;

/**
 * ================================================================
 * STEP 8d: OAUTH2 USER INFO FACTORY
 * ================================================================
 *
 * WHY a Factory?
 * DESIGN PATTERN: Factory Method.
 *
 * The problem: OAuth2UserService receives attributes from an unknown provider.
 * It doesn't want to contain a big if-else to decide which class to instantiate.
 * We centralise that decision here.
 *
 * Before factory:
 *   if (provider.equals("google"))       return new GoogleOAuth2UserInfo(attrs);
 *   else if (provider.equals("github"))  return new GitHubOAuth2UserInfo(attrs);
 *   ... scattered throughout the code
 *
 * After factory:
 *   OAuth2UserInfoFactory.getOAuth2UserInfo(registrationId, attributes)
 *   → one line anywhere in the codebase
 *   → adding a new provider = add one case in the factory only
 *
 * WHY static method?
 * This factory has no state to maintain.
 * A static utility method is simpler than instantiating a factory object.
 * Called as: OAuth2UserInfoFactory.getOAuth2UserInfo("google", attrs)
 *
 * INTERVIEW TIP — "What is the Factory pattern?"
 * Creates objects without the caller needing to know the concrete class.
 * The caller knows the INTERFACE (OAuth2UserInfo), not the implementation
 * (GoogleOAuth2UserInfo or GitHubOAuth2UserInfo).
 * Open/Closed Principle: adding a new provider doesn't change the callers.
 */
public class OAuth2UserInfoFactory {
    /*
     * WHY private constructor?
     * Prevents instantiation of this utility class.
     * All methods are static — there's no reason to create an instance.
     * This is a common pattern for utility/helper classes.
     */
    private OAuth2UserInfoFactory(){}
    /*
     * WHY String registrationId (not AuthProvider enum)?
     * Spring Security's OAuth2 auto-configuration identifies providers
     * by their registration ID as a String ("google", "github").
     * This is the value from spring.security.oauth2.client.registration.{id}.
     * We use toLowerCase() to make the switch case-insensitive.
     */

    public static OAuth2UserInfo getOAuth2UserInfo(String registrationId, Map<String, Object> attributes){
        return switch (registrationId.toLowerCase()){
            case "google" -> new GoogleOAuth2UserInfo(attributes);
            case "github" -> new GitHubAuth2UserInfo(attributes);
            /*
             * WHY throw an exception for unknown providers?
             * If a new provider is added to application.properties but
             * not to this factory, we fail FAST with a clear message
             * instead of silently using null or wrong data.
             * Fast-fail is a best practice for configuration errors.
             */
            default -> throw new AppExceptions.OAuth2AuthenticationException("Unsupported OAuth2 provider"+ registrationId);
        };
    }
}
