package com.iqbalitsmy.users_api.model;

import jakarta.persistence.*;
import jakarta.validation.constraints.Email;
import lombok.*;


@Entity
@Table(name="users")
@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class User {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Email(message = "Enter valid email")
    @Column(unique = true, nullable = false, length = 150)
    private String email;
    @Column(nullable = false, length = 100)
    private String name;

    @Column(length = 200)
    private String imageUrl;

    @Column
    private String password;

    @Column(nullable = false)
    private boolean emailVerified =false;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 20)
    private AuthProvider provider;

    @Column
    private String providerId;

    @Column(nullable = false, length = 20)
    @Builder.Default
    private String role = "ROLE_USER";

    @Column(nullable = false)
    @Builder.Default
    private boolean active=true;
}
