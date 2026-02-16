package com.ultrasystem.erp.common.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfTokenRequestAttributeHandler;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.List;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            // ----------------------------------------------------------------
            // CORS — only allow requests from the frontend origin
            // ----------------------------------------------------------------
            .cors(cors -> cors.configurationSource(corsConfigurationSource()))

            // ----------------------------------------------------------------
            // CSRF
            // API endpoints → disabled (use Authorization header, not cookie)
            // /auth/refresh → enabled with double submit cookie pattern
            //   server sets XSRF-TOKEN cookie (readable by JS)
            //   client reads it and sends back in X-XSRF-TOKEN header
            //   server checks both match → attacker can't forge the header
            // ----------------------------------------------------------------
            .csrf(csrf -> csrf
                .ignoringRequestMatchers("/api/v1/erp_ultrasystem/**")
                .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
                .csrfTokenRequestHandler(new CsrfTokenRequestAttributeHandler())
            )

            // ----------------------------------------------------------------
            // Stateless — no server-side session, every request carries JWT
            // ----------------------------------------------------------------
            .sessionManagement(session -> session
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
            )

            // ----------------------------------------------------------------
            // Authorization rules
            // ----------------------------------------------------------------
            .authorizeHttpRequests(auth -> auth
                // public endpoints — no token needed
                .requestMatchers("/actuator/health").permitAll()
                .requestMatchers("/auth/login").permitAll()
                .requestMatchers("/auth/signup").permitAll()

                // refresh token endpoint — authenticated but no scope check
                // CSRF protection above handles the security here
                .requestMatchers("/auth/refresh").authenticated()

                // all ERP APIs require the write scope
                .requestMatchers("/api/v1/erp_ultrasystem/**")
                    .hasAuthority("SCOPE_erp_ultrasystem.write")

                // everything else must be authenticated
                .anyRequest().authenticated()
            )

            // ----------------------------------------------------------------
            // OAuth2 JWT resource server
            // Spring fetches Keycloak public key from issuer-uri in application.yml
            // and validates every token signature automatically
            // ----------------------------------------------------------------
            .oauth2ResourceServer(oauth2 -> oauth2
                .jwt(jwt -> jwt
                    .jwtAuthenticationConverter(jwtAuthenticationConverter())
                )
            );

        return http.build();
    }

    // ----------------------------------------------------------------
    // Extract scope claim from JWT and prefix with SCOPE_
    // so hasAuthority("SCOPE_erp_ultrasystem.write") works
    // ----------------------------------------------------------------
    @Bean
    public JwtAuthenticationConverter jwtAuthenticationConverter() {
        JwtGrantedAuthoritiesConverter authoritiesConverter = new JwtGrantedAuthoritiesConverter();
        authoritiesConverter.setAuthoritiesClaimName("scope");
        authoritiesConverter.setAuthorityPrefix("SCOPE_");

        JwtAuthenticationConverter jwtConverter = new JwtAuthenticationConverter();
        jwtConverter.setJwtGrantedAuthoritiesConverter(authoritiesConverter);
        return jwtConverter;
    }

    // ----------------------------------------------------------------
    // CORS — only the frontend origin is allowed
    // evil-site.com is blocked from reading responses
    // ----------------------------------------------------------------
    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration config = new CorsConfiguration();

        config.setAllowedOrigins(List.of(
            "http://localhost:3000",          // local dev
            "https://app.ultrasystem.com"     // production frontend
        ));
        config.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "OPTIONS"));
        config.setAllowedHeaders(List.of(
            "Authorization",
            "Content-Type",
            "X-XSRF-TOKEN",     // double submit CSRF header for /auth/refresh
            "Idempotency-Key"   // idempotency header for mutating API calls
        ));
        config.setAllowCredentials(true); // required for cookies (refresh token)
        config.setMaxAge(3600L);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", config);
        return source;
    }
}
