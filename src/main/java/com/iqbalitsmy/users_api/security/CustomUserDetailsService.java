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

@Service
@RequiredArgsConstructor
@Slf4j
public class CustomUserDetailsService implements UserDetailsService {
    private final UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        if (username == null || username.isBlank()){
            log.warn("Invalid email in loadUserByUsername");
            throw new UsernameNotFoundException("Invalid Credential");
        }

        User user = userRepository.findByEmail(username)
                .orElseThrow(() -> {
                    log.warn("User not found for: {}",username);
                    return new UsernameNotFoundException("Invalid credential");
                });
        if (!user.isActive()){
            log.warn("Deactivated user attempt to access: {}",user.getEmail());
            throw new UsernameNotFoundException("Invalid credential");
        }

        return new org.springframework.security.core.userdetails.User(
                user.getEmail(),
                user.getPassword() != null ? user.getPassword() : "",
                List.of(new SimpleGrantedAuthority(user.getRole()))
        );
    }
}
