package com.iqbalitsmy.users_api.security.oauth2;

import java.util.Map;
/**
 * ================================================================
 * STEP 8b: GOOGLE OAUTH2 USER INFO
 * ================================================================
 *
 * WHY a separate class for Google?
 * Google's user info endpoint returns attributes with Google-specific
 * field names. This class maps those fields to our standard interface.
 *
 * Google's fields (from https://openid.net/connect/ - standard OIDC):
 *   "sub"     → the stable, unique user ID at Google (OpenID Connect subject)
 *   "name"    → full display name
 *   "email"   → email address
 *   "picture" → URL of the profile photo
 *
 * WHY use "sub" as the ID?
 * Google recommends using "sub" (subject) as the unique identifier.
 * It never changes, even if the user changes their email address.
 * This is the OpenID Connect standard for user identity.
 */

public class GoogleOAuth2UserInfo extends OAuth2UserInfo{
    public GoogleOAuth2UserInfo(Map<String, Object> attributes){
        super(attributes);
    }

    @Override
    public String getId() {
        // "sub" is the stable, unique Google user identifier (OIDC standard)
        return (String) attributes.get("sub");
    }

    @Override
    public String getName() {
        return (String) attributes.get("name");
    }

    @Override
    public String getEmail() {
        return (String) attributes.get("email");
    }

    @Override
    public String getImageUrl() {
        // "picture" is Google's field for the profile photo URL
        return (String) attributes.get("picture");
    }
}
