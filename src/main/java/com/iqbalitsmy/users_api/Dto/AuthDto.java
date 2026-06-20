package com.iqbalitsmy.users_api.Dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.*;

public class AuthDto {

    @Getter
    @Setter
    @AllArgsConstructor
    @NoArgsConstructor
    @Builder
    public  static class RegisterRequest{
        @NotBlank(message = "Name is required")
        @Size(min = 2, max = 100, message = "Name must be 2-100 character")
        private String name;

        @NotBlank(message = "Email is required")
        @Email(message = "Email must be valid formate")
        private String email;

        @NotBlank(message = "Password is required")
        @Size(min = 3, max = 100, message = "Password must be at least character")
        private String password;
    }

    @Getter
    @Setter
    @AllArgsConstructor
    @NoArgsConstructor
    @Builder
    public  static class LoginRequest{

        @NotBlank(message = "Email is required")
        @Email(message = "Email must be valid formate")
        private String email;

        @NotBlank(message = "Password is required")
        private String password;
    }

    @Getter
    @Setter
    @AllArgsConstructor
    @NoArgsConstructor
    @Builder
    public static class TokenResponse{
        private String accessToken;
        private String refreshToken;
        private String tokenType="Bearer";
        private long accessTokenExpireIn;
        private String email;
        private String role;
        private String provider;
    }

    @Getter
    @Setter
    @AllArgsConstructor
    @NoArgsConstructor
    @Builder
    public static class RefreshRequest{
        @NotBlank(message = "Refresh token is required")
        private String refreshToken;
    }

    @Getter
    @Setter
    @AllArgsConstructor
    @NoArgsConstructor
    @Builder
    public static class  UserResponse{
        private Long id;
        private String name;
        private String email;
        private String imageUrl;
        private boolean emailVerified;
        private String role;
        private String provider;
        private boolean active;
    }

    @Getter
    @Setter
    @AllArgsConstructor
    @NoArgsConstructor
    @Builder
    public static class UpdateProfileRequest{
        @NotBlank(message = "Name is required")
        @Size(min = 2, max = 100, message = "Name must be 2-100 character")
        private String name;
    }
}
