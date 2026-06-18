package com.iqbalitsmy.users_api.security.oauth2;

import java.util.Map;

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
        return (String) attributes.get("email");
    }

    @Override
    public String getImageUrl() {
        return (String) attributes.get("avatar_url");
    }
}
