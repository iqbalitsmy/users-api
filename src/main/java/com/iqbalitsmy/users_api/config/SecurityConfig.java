package com.iqbalitsmy.users_api.config;

import com.iqbalitsmy.users_api.security.CustomUserDetailsService;
import com.iqbalitsmy.users_api.security.jwt.JwtAuthenticationFilter;
import com.iqbalitsmy.users_api.security.oauth2.CustomOAuth2UserService;
import com.iqbalitsmy.users_api.security.oauth2.OAuth2AuthenticationFailerHandler;
import com.iqbalitsmy.users_api.security.oauth2.OAuth2AuthenticationSuccessHandler;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
@RequiredArgsConstructor
public class SecurityConfig {
    private final CustomUserDetailsService userDetailsService;
    private final CustomOAuth2UserService customOAuth2UserService;
    private final JwtAuthenticationFilter jwtAuthenticationFilter;
    private final OAuth2AuthenticationSuccessHandler oAuth2SuccessHandler;
    private final OAuth2AuthenticationFailerHandler oAuth2FailerHandler;

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public AuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider(userDetailsService);
        provider.setPasswordEncoder(passwordEncoder());
        return provider;
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) {
        return config.getAuthenticationManager();
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .csrf(csrf -> csrf.disable())
                .sessionManagement(
                        session ->
                                session.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                )
                .authorizeHttpRequests(
                        auth ->
                                auth
                                        .requestMatchers("/auth/**").permitAll()
                                        .requestMatchers("/oauth2/**").permitAll()
                                        .requestMatchers("/login/oauth2/**").permitAll()
                                        .requestMatchers("/h2-console/**").permitAll()
                                        .requestMatchers("/api/users/all").hasRole("ADMIN")
                                        .requestMatchers("/api/users/**").hasRole("ADMIN")
                                        .anyRequest().authenticated()
                )
                .oauth2Login(
                        oauth2 ->
                                oauth2
                                        .userInfoEndpoint(
                                                userInfo ->
                                                        userInfo.userService(customOAuth2UserService)
                                        )
                                        .successHandler(oAuth2SuccessHandler)
                                        .failureHandler(oAuth2FailerHandler)
                )
                .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
                .authenticationProvider(authenticationProvider())
                .headers(
                        headers ->
                                headers.frameOptions(frame -> frame.sameOrigin())
                );
        return http.build();
    }


}
