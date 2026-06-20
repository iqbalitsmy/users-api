package com.iqbalitsmy.users_api.config;

import com.iqbalitsmy.users_api.model.AuthProvider;
import com.iqbalitsmy.users_api.model.User;
import com.iqbalitsmy.users_api.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
@Slf4j
public class DataInitializer implements CommandLineRunner {
    private final UserRepository userRepository;
    private final PasswordEncoder encoder;

    @Override
    public void run(String... args) throws Exception {
        log.info("=== seeding initial data ===");

        if (!userRepository.existsByEmail("admin@example.com")) {
            userRepository.save(
                    User.builder()
                            .name("Admin user")
                            .email("admin@example.com")
                            .password(encoder.encode("admin123"))
                            .provider(AuthProvider.LOCAL)
                            .providerId(null)
                            .emailVerified(true)
                            .role("ROLE_ADMIN")
                            .active(true)
                            .build()
            );
            log.info("Seeding -> admin@example.com / admin123 (ROLE_ADMIN)");
        }
        if (!userRepository.existsByEmail("user@example.com")) {
            userRepository.save(
                    User.builder()
                            .name("Admin user")
                            .email("user@example.com")
                            .password(encoder.encode("user123"))
                            .provider(AuthProvider.LOCAL)
                            .providerId(null)
                            .emailVerified(true)
                            .role("ROLE_USER")
                            .active(true)
                            .build()
            );
            log.info("Seeding -> user@example.com / user123 (ROLE_USER)");
        }

        log.info("===== Seeding complete. total user: {}", userRepository.count());
    }
}
