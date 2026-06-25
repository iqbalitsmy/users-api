package com.iqbalitsmy.users_api.repository;

import com.iqbalitsmy.users_api.model.RefreshToken;
import com.iqbalitsmy.users_api.model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;

import java.util.Optional;

/**
 * ================================================================
 * STEP 3b: REFRESH TOKEN REPOSITORY
 * ================================================================
 * <p>
 * WHY a separate repository for refresh tokens?
 * Refresh tokens are a security-critical, independently managed entity.
 * They have their own lifecycle: create on login, find on refresh,
 * delete on logout. Keeping them in their own repository keeps the
 * code organized and the User repository focused on user data only.
 */
public interface RefreshTokenRepository extends JpaRepository<RefreshToken, Long> {
    Optional<RefreshToken> findByToken(String token);

    Optional<RefreshToken> findByUser(User user);
    /*
     * WHY @Modifying + @Query for delete?
     * Spring Data JPA can only auto-derive SELECT and simple DELETE by ID.
     * For "DELETE WHERE user = ?" we need a custom @Query.
     *
     * WHY @Modifying?
     * Tells Spring Data JPA that this query modifies data (not a SELECT).
     * Required for @Query annotations that execute INSERT/UPDATE/DELETE.
     * Without it, Spring throws "Executing an update/delete query" error.
     *
     * WHY JPQL (not SQL)?
     * @Query uses JPQL (Java Persistence Query Language) by default.
     * JPQL operates on entity class names and field names, not table/column names.
     * This makes it DB-agnostic — works with H2, MySQL, PostgreSQL unchanged.
     * "RefreshToken" = entity class, "rt.user" = the user field in RefreshToken.
     */

    @Modifying
    @Query("DELETE FROM RefreshToken rt WHERE rt.user = :user")
    void deleteByUser(User user);

}
