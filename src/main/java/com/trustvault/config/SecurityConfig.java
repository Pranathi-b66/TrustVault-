package com.trustvault.config;

import com.trustvault.entity.AuditAction;
import com.trustvault.entity.AuditStatus;
import com.trustvault.security.CustomUserDetailsService;
import com.trustvault.security.JwtAuthenticationFilter;
import com.trustvault.security.UserAccountStatusFilter;
import com.trustvault.service.AuditLogService;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.util.HashMap;
import java.util.Map;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {

    private final JwtAuthenticationFilter jwtAuthenticationFilter;
    private final UserAccountStatusFilter userAccountStatusFilter;
    private final CustomUserDetailsService customUserDetailsService;
    private final AuditLogService auditLogService;

    public SecurityConfig(JwtAuthenticationFilter jwtAuthenticationFilter,
                          UserAccountStatusFilter userAccountStatusFilter,
                          CustomUserDetailsService customUserDetailsService,
                          AuditLogService auditLogService) {
        this.jwtAuthenticationFilter = jwtAuthenticationFilter;
        this.userAccountStatusFilter = userAccountStatusFilter;
        this.customUserDetailsService = customUserDetailsService;
        this.auditLogService = auditLogService;
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public DaoAuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
        authProvider.setUserDetailsService(customUserDetailsService);
        authProvider.setPasswordEncoder(passwordEncoder());
        return authProvider;
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authConfig) throws Exception {
        return authConfig.getAuthenticationManager();
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .csrf(AbstractHttpConfigurer::disable)
            .cors(AbstractHttpConfigurer::disable)
            .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .exceptionHandling(exceptions -> exceptions
                .authenticationEntryPoint((request, response, authException) -> {
                    response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                    response.setContentType("application/json");
                    response.getWriter().write("{\"status\":401,\"error\":\"Unauthorized\",\"message\":\"Authentication required to access protected resource.\"}");
                })
                .accessDeniedHandler((request, response, accessDeniedException) -> {
                    String clientIp = request.getHeader("X-Forwarded-For");
                    if (clientIp == null || clientIp.isBlank()) {
                        clientIp = request.getRemoteAddr();
                    }

                    Map<String, Object> details = new HashMap<>();
                    details.put("reason", accessDeniedException.getMessage());
                    details.put("uri", request.getRequestURI());
                    details.put("method", request.getMethod());

                    auditLogService.logEvent(
                            null,
                            request.getUserPrincipal() != null ? request.getUserPrincipal().getName() : "anonymous",
                            AuditAction.ACCESS_DENIED,
                            null,
                            clientIp,
                            AuditStatus.FAILURE,
                            details
                    );

                    response.setStatus(HttpServletResponse.SC_FORBIDDEN);
                    response.setContentType("application/json");
                    response.getWriter().write("{\"status\":403,\"error\":\"Forbidden\",\"message\":\"Access denied. Zero-trust security policy violated.\"}");
                })
            )
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/api/auth/biometric", "/api/auth/biometric/**").authenticated()
                .requestMatchers(
                        "/",
                        "/index.html",
                        "/css/**",
                        "/js/**",
                        "/favicon.ico",
                        "/favicon.svg",
                        "/api/auth/**",
                        "/error"
                ).permitAll()
                .requestMatchers("/api/admin/**").hasRole("ADMIN")
                .requestMatchers("/api/documents/**").authenticated()
                .anyRequest().authenticated()
            )
            .authenticationProvider(authenticationProvider())
            .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
            .addFilterAfter(userAccountStatusFilter, JwtAuthenticationFilter.class);

        return http.build();
    }
}
