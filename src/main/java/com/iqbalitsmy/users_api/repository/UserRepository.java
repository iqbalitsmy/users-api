package com.iqbalitsmy.users_api.repository;

import com.iqbalitsmy.users_api.model.AuthProvider;
import com.iqbalitsmy.users_api.model.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Long> {

    Optional<User> findByEmail(String email);

    Optional<User> findByProviderAndProviderId(AuthProvider provider, String providerId);

    boolean existsByEmail(String email);
}
