package com.iqbalitsmy.users_api.security.oauth2;

import java.util.Map;
/**
 * ================================================================
 * STEP 8a: OAUTH2 USER INFO — ABSTRACTION LAYER
 * ================================================================
 *
 * WHY an abstract class for OAuth2UserInfo?
 *
 * The PROBLEM: Every OAuth2 provider returns user data in a different format.
 *
 *   Google returns:
 *   {
 *     "sub":     "107312345678901234567",  ← unique ID
 *     "name":    "John Doe",
 *     "email":   "john@gmail.com",
 *     "picture": "https://lh3.googleusercontent.com/..."
 *   }
 *
 *   GitHub returns:
 *   {
 *     "id":         12345678,              ← numeric ID (not "sub"!)
 *     "name":       "John Doe",
 *     "email":      "john@users.noreply.github.com",
 *     "avatar_url": "https://avatars.githubusercontent.com/..."  ← different key!
 *   }
 *
 * Each provider uses different FIELD NAMES for the same concepts.
 * We normalise them behind a common interface:
 *   getId()       → always returns the unique ID regardless of provider
 *   getName()     → always returns the display name
 *   getEmail()    → always returns the email
 *   getImageUrl() → always returns the profile picture URL
 *
 * Then our OAuth2UserService doesn't need to know which provider sent the data.
 * It just calls .getId(), .getEmail() etc. on any OAuth2UserInfo instance.
 *
 * DESIGN PATTERN: This is the ADAPTER pattern.
 * We adapt provider-specific data formats to a common interface.
 */

public abstract class OAuth2UserInfo {
    // WHY protected? Subclasses access this map to extract fields.
    protected Map<String, Object> attributes;

    public OAuth2UserInfo(Map<String, Object> attributes) {
        this.attributes = attributes;
    }
    // Stable unique ID from the provider (never changes for this user)
    public abstract String getId();

    public abstract String getName();

    public abstract String getEmail();

    public abstract String getImageUrl();
    // WHY expose raw attributes? Some code may need provider-specific fields.
    public Map<String, Object> getAttributes() {
        return attributes;
    }
}
