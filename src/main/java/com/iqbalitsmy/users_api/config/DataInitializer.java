package com.iqbalitsmy.users_api.config;

import com.iqbalitsmy.users_api.model.AuthProvider;
import com.iqbalitsmy.users_api.model.User;
import com.iqbalitsmy.users_api.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

/**
 * ================================================================
 * STEP 19: DATA INITIALIZER — Seed Data on Startup
 * ================================================================
 *
 * WHY CommandLineRunner?
 * Spring Boot calls run() AFTER the complete ApplicationContext is ready:
 *  - All beans are created
 *  - DB is connected
 *  - Hibernate has created the tables (ddl-auto=create-drop)
 *
 * This is the right moment to insert seed data.
 * If we ran before Hibernate created the tables, the INSERT would fail.
 *
 * WHY @Component?
 * Registers this as a Spring bean. CommandLineRunner beans are discovered
 * automatically and their run() method is called on startup.
 *
 * WHY seed an ADMIN user?
 * H2 is in-memory — it resets on every restart.
 * Without seeding, there would be no admin account to use immediately.
 * In production with a persistent DB, seed data runs once (use data.sql or Flyway).
 */
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
