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

@Service
@RequiredArgsConstructor
@Slf4j
public class UserService {
    private final UserRepository userRepository;

    // ── GET OWN PROFILE ──────────────────────────────────────────
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
