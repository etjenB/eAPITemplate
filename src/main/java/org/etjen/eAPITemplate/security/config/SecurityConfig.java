package org.etjen.eAPITemplate.security.config;

import lombok.RequiredArgsConstructor;
import org.etjen.eAPITemplate.config.properties.http.CorsProperties;
import org.etjen.eAPITemplate.security.jwt.JwtAuthenticationFilter;
import org.etjen.eAPITemplate.security.jwt.JwtService;
import org.etjen.eAPITemplate.security.user.UserDetailsServiceImpl;
import org.springframework.context.annotation.*;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.builders.*;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.config.http.*;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.etjen.eAPITemplate.security.provider.CustomAuthenticationProvider;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.List;

@Configuration
@EnableMethodSecurity(prePostEnabled = true)
@RequiredArgsConstructor
public class SecurityConfig {
    private final CorsProperties corsProperties;

    @Bean
    public JwtAuthenticationFilter jwtFilter(JwtService jwtService,
                                             UserDetailsServiceImpl userDetailsService) {
        return new JwtAuthenticationFilter(jwtService, userDetailsService);
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder(); //Argon2id primary, BCrypt fallback - Spring-Security default as of 6.3 and fares better on GPUs than BCrypt
    }

    @Bean
    public AuthenticationManager authManager(HttpSecurity http, CustomAuthenticationProvider customAuthProvider) throws Exception {
        return http
                .authenticationProvider(customAuthProvider)
                .getSharedObject(AuthenticationManagerBuilder.class)
                .build();
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http, JwtAuthenticationFilter jwtFilter) throws Exception {
        http
                // ! cors set to read the allowed-origins from environment e.g. application properties
            .cors(cors -> cors.configurationSource(corsConfigurationSource()))
                // ! do not need csrf because I do not have a frontend html and I implement jwt anyways
            .csrf(AbstractHttpConfigurer::disable)
                // ! we do not maintain a session for user on the backend because we will keep jwt on frontend
            .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                // ! paths public, auth and actuator are open to everyone, admin path is only for logged in user and user with admin role
                // ! user is path for already logged in user with either role user or role admin
                // ! all other paths are only for logged in user
            .authorizeHttpRequests(
                    auth -> auth
                                                            .requestMatchers("/user/**", "/auth/sessions/**").hasAnyRole("USER","ADMIN")
                                                            .requestMatchers("/admin/**").hasRole("ADMIN")
                                                            .requestMatchers("/test/public/**", "/auth/**", "/actuator/**").permitAll()
                                                            .anyRequest().authenticated()
            )
            .headers(headers -> headers
                // * 1) HSTS (Strict-Transport-Security)
                .httpStrictTransportSecurity(hsts -> hsts
                        .includeSubDomains(true)
                        .maxAgeInSeconds(31536000)
                )
                // * 2) X-Content-Type-Options: nosniff
                .contentTypeOptions(Customizer.withDefaults())
                // * 3) X-Frame-Options: DENY
                .frameOptions(HeadersConfigurer.FrameOptionsConfig::deny)
                // * 4) CONTENT-SECURITY-POLICY header
                .contentSecurityPolicy(csp -> csp
                        .policyDirectives(
                                "default-src 'self'; " +
                                "script-src 'self' https://cdnjs.cloudflare.com; " +
                                "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; " +
                                "font-src 'self' https://fonts.gstatic.com; " +
                                "img-src 'self' data:; " +
                                "object-src 'none'; " +
                                "frame-ancestors 'none'; " +
                                "base-uri 'self';"
                        )
                )
            )
            .addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration config = new CorsConfiguration();

        // * 2) Read the property, split on commas, turn into a List<String>
        String originsProperty = corsProperties.allowedOrigins();
        // ? If the property is missing, default to an empty string to avoid NPE
        if (originsProperty == null) {
            originsProperty = "";
        }
        List<String> allowedOrigins = List.of(originsProperty.split(","));
        config.setAllowedOrigins(allowedOrigins);

        config.setAllowedMethods(List.of(
                HttpMethod.GET.name(),
                HttpMethod.POST.name(),
                HttpMethod.PUT.name(),
                HttpMethod.DELETE.name(),
                HttpMethod.OPTIONS.name()
        ));

        config.setAllowedHeaders(List.of("Authorization", "Content-Type", "X-Requested-With"));

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", config);
        return source;
    }
}
