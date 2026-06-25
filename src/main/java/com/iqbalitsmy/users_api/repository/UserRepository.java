package com.iqbalitsmy.users_api.repository;

import com.iqbalitsmy.users_api.model.AuthProvider;
import com.iqbalitsmy.users_api.model.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;
/**
 * ================================================================
 * STEP 3a: USER REPOSITORY
 * ================================================================
 *
 * WHY extend JpaRepository<User, Long>?
 * Spring Data JPA generates ALL implementations at runtime.
 * Free methods: save, findById, findAll, deleteById, existsById, count.
 *
 * WHY @Repository?
 * Enables Spring's exception translation — converts raw Hibernate
 * exceptions into Spring's DataAccessException hierarchy.
 * Also makes the intent of the class explicit.
 *
 * INTERVIEW TIP — "How does Spring Data derive queries from method names?"
 * Spring parses the method name and generates the SQL:
 *   findByEmail              → SELECT * FROM users WHERE email = ?
 *   findByProviderAndProviderId → SELECT * FROM users WHERE provider = ? AND provider_id = ?
 *   existsByEmail            → SELECT COUNT(*) > 0 WHERE email = ?
 */
public interface UserRepository extends JpaRepository<User, Long> {

    /*
     * WHY Optional<User>?
     * findByEmail may return nothing (user doesn't exist).
     * Optional forces us to handle the empty case — no NullPointerException.
     * .orElseThrow() is the idiomatic way to handle missing values.
     */
    Optional<User> findByEmail(String email);


    /*
     * WHY findByProviderAndProviderId?
     * Used during OAuth2 login to find the existing account for a returning user.
     * We match on BOTH provider AND providerId because:
     *  - Same email could exist for different providers (edge case)
     *  - providerId is the stable, immutable identifier at each provider
     *
     * Spring generates:
     * SELECT * FROM users WHERE provider = ? AND provider_id = ?
     */
    Optional<User> findByProviderAndProviderId(AuthProvider provider, String providerId);

    boolean existsByEmail(String email);
}
