package com.iqbalitsmy.users_api.security.oauth2;

import com.iqbalitsmy.users_api.exception.AppExceptions;

import java.util.Map;

public class OAuth2UserInfoFactory {
    private OAuth2UserInfoFactory(){}

    public static OAuth2UserInfo getOAuth2UserInfo(String registrationId, Map<String, Object> attributes){
        return switch (registrationId.toLowerCase()){
            case "google" -> new GoogleOAuth2UserInfo(attributes);
            case "github" -> new GitHubAuth2UserInfo(attributes);
            default -> throw new AppExceptions.OAuth2AuthenticationException("Unsupported OAuth2 provider"+ registrationId);
        };
    }
}
