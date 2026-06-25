package com.iqbalitsmy.users_api.security.oauth2;

import java.util.Map;
/**
 * ================================================================
 * STEP 8c: GITHUB OAUTH2 USER INFO
 * ================================================================
 *
 * WHY a separate class for GitHub?
 * GitHub's user info endpoint returns completely different field names
 * from Google. This class maps them to our standard interface.
 *
 * GitHub's fields (from https://docs.github.com/en/rest/users/users):
 *   "id"         → numeric user ID (e.g., 12345678) — NOTE: it's an Integer, not String!
 *   "name"       → display name (can be null if not set in profile)
 *   "email"      → may be null if user has set their email to private!
 *   "avatar_url" → URL of the profile photo
 *   "login"      → username (e.g., "johndoe") — fallback if name is null
 *
 * WHY handle null name with login fallback?
 * GitHub users can leave their "name" field empty in their profile.
 * The "login" (username) is always set. We use it as a fallback.
 *
 * WHY String.valueOf() for the ID?
 * GitHub returns the user ID as an Integer in the JSON.
 * Our abstract class and DB store it as a String.
 * String.valueOf() safely converts Integer → String.
 * Using (String) cast directly would throw ClassCastException.
 */

public class GitHubAuth2UserInfo extends OAuth2UserInfo{
    public GitHubAuth2UserInfo(Map<String, Object> attributes){
        super(attributes);
    }

    @Override
    public String getId() {
        return String.valueOf(attributes.get("id"));
    }

    @Override
    public String getName() {
         String name =  (String) attributes.get("name");
        return (name != null && !name.isBlank() ? name : (String) attributes.get("login"));
    }

    @Override
    public String getEmail() {
        /*
         * WHY may be null?
         * GitHub users can set their email as private in their profile settings.
         * When email is private, the /user endpoint returns null for email.
         * To get the email reliably, you'd need to call /user/emails separately.
         * For simplicity, we handle the null case in OAuth2UserService.
         */
        return (String) attributes.get("email");
    }

    @Override
    public String getImageUrl() {
        // GitHub uses "avatar_url" instead of "picture" (Google uses "picture")
        return (String) attributes.get("avatar_url");
    }
}
