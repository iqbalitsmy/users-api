package com.iqbalitsmy.users_api.service;

import com.iqbalitsmy.users_api.Dto.AuthDto;
import com.iqbalitsmy.users_api.exception.AppExceptions;
import com.iqbalitsmy.users_api.model.User;
import com.iqbalitsmy.users_api.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.stream.Collectors;

/**
 * ================================================================
 * STEP 14: USER SERVICE — Profile Management
 * ================================================================
 *
 * WHY separate from AuthService?
 * AuthService handles identity (who you are, tokens).
 * UserService handles data (your profile, admin operations).
 * Single Responsibility Principle — each class has one reason to change.
 *
 * DESIGN NOTE — What operations does this service expose?
 *  - getProfile(email)           → any authenticated user reads their profile
 *  - updateProfile(email, req)   → any authenticated user updates their own name
 *  - getAllUsers()                → ADMIN only — list all users
 *  - getUserById(id)             → ADMIN only — look up any user
 *  - deactivateUser(id)          → ADMIN only — soft delete
 *
 * WHY not allow users to change their email here?
 * Email changes require re-verification and provider re-linking.
 * That's a separate, security-sensitive flow beyond this scope.
 * For OAuth2 users, email comes from the provider anyway.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class UserService {
    private final UserRepository userRepository;


    // ── GET OWN PROFILE ──────────────────────────────────────────

    /*
     * WHY readOnly = true?
     * Tells Hibernate not to track dirty state for this transaction.
     * No entities will be modified — skipping dirty checking is faster.
     * Always add readOnly=true to methods that only read data.
     */
    @Transactional(readOnly = true)
    public AuthDto.UserResponse getUser(String email) {
        User user = userRepository.findByEmail(email).orElseThrow(
                () -> new AppExceptions.ResourceNotFoundException("User not found for :" + email)
        );

        return mapToResponse(user);
    }

    // ── UPDATE OWN PROFILE ────────────────────────────────────────
    @Transactional
    public AuthDto.UserResponse updateProfile(String email, AuthDto.UpdateProfileRequest request) {
        User user = userRepository.findByEmail(email).orElseThrow(
                () -> new AppExceptions.ResourceNotFoundException("User not found for :" + email)
        );

        user.setName(request.getName());
        /*
         * WHY no explicit save() call?
         * Inside @Transactional, Hibernate tracks changes to managed entities
         * (dirty checking). When the transaction commits, it auto-generates
         * UPDATE SQL for changed fields. This is called "dirty checking."
         * Calling save() here is redundant but not wrong.
         */
        return mapToResponse(user);
    }

    // ── ADMIN: GET ALL USERS ──────────────────────────────────────
    @Transactional(readOnly = true)
    public List<AuthDto.UserResponse> getAllUsers() {
        return userRepository.findAll()
                .stream()
                .map(this::mapToResponse)
                .collect(Collectors.toList());
    }

    // ── ADMIN: GET USER BY ID ─────────────────────────────────────
    @Transactional(readOnly = true)
    public AuthDto.UserResponse getUserById(Long id) {
        User user = userRepository.findById(id).orElseThrow(
                () -> new AppExceptions.ResourceNotFoundException("User not found with id:" + id)
        );
        return mapToResponse(user);
    }

    // ── ADMIN: DEACTIVATE USER ────────────────────────────────────
    /*
     * WHY soft delete (active = false) instead of hard delete?
     *  - Audit trail: we can see who existed
     *  - Foreign key safety: related data (tokens, logs) remains intact
     *  - Recovery: reactivate if deactivated by mistake
     *  - JWT kill switch: CustomUserDetailsService rejects inactive users,
     *    so their existing JWT stops working immediately on next request
     */
    @Transactional
    public void deactivateUser(Long id) {
        User user = userRepository.findById(id).orElseThrow(
                () -> new AppExceptions.ResourceNotFoundException("User not found with id:" + id)
        );

        user.setActive(false);
    }

    private AuthDto.UserResponse mapToResponse(User user) {
        return AuthDto.UserResponse.builder()
                .id(user.getId())
                .name(user.getName())
                .email(user.getEmail())
                .imageUrl(user.getImageUrl())
                .emailVerified(user.isEmailVerified())
                .role(user.getRole()).provider(user.getProvider().name())
                .active(user.isActive()).build();
    }
}
