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

@Service
@RequiredArgsConstructor
@Slf4j
public class CustomOAuth2UserService extends DefaultOAuth2UserService {
    private final UserRepository userRepository;

    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        OAuth2User oAuth2User = super.loadUser(userRequest);

        try {
            return processOAuth2User(userRequest, oAuth2User);
        } catch (AppExceptions.OAuth2AuthenticationException ex) {
            throw new OAuth2AuthenticationException(ex.getMessage());
        }
    }

    private OAuth2User processOAuth2User(OAuth2UserRequest userRequest, OAuth2User oAuth2User) {
        String registrationId = userRequest.getClientRegistration().getRegistrationId();
        log.debug("processing OAuth2 user from provider: {}", registrationId);

        OAuth2UserInfo userInfo = OAuth2UserInfoFactory.getOAuth2UserInfo(registrationId, oAuth2User.getAttributes());

        if (userInfo.getEmail() == null && userInfo.getEmail().isBlank()) {
            throw new AppExceptions.OAuth2AuthenticationException("Email not provided by " + registrationId + ". Please make your email public in your " + registrationId + "settings.");
        }

        AuthProvider provider = AuthProvider.valueOf(registrationId.toUpperCase());

        User user = findOrCreateUser(userInfo, provider);

        Map<String, Object> attributes = new HashMap<>(oAuth2User.getAttributes());
        attributes.put("email", userInfo.getEmail());

        return new DefaultOAuth2User(
                List.of(new SimpleGrantedAuthority(user.getRole())),
                attributes,
                "email"
        );
    }

    private User findOrCreateUser(OAuth2UserInfo userInfo, AuthProvider provider) {
        Optional<User> existingOAuth2User = userRepository.findByProviderAndProviderId(provider, userInfo.getId());

        // Case 1: Returning OAuth2 user — find by provider + their ID at that provider
        if (existingOAuth2User.isPresent()) {
            User user = existingOAuth2User.get();
            log.info("Returning OAuth2 user: {} via {}", user.getEmail(), provider);

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
