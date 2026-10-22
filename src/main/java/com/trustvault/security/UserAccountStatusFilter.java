package com.trustvault.security;

import com.trustvault.entity.AuditAction;
import com.trustvault.entity.AuditStatus;
import com.trustvault.entity.User;
import com.trustvault.entity.UserStatus;
import com.trustvault.repository.UserRepository;
import com.trustvault.service.AuditLogService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

@Component
public class UserAccountStatusFilter extends OncePerRequestFilter {

    private final UserRepository userRepository;
    private final AuditLogService auditLogService;

    public UserAccountStatusFilter(UserRepository userRepository, AuditLogService auditLogService) {
        this.userRepository = userRepository;
        this.auditLogService = auditLogService;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        if (authentication != null && authentication.isAuthenticated() && authentication.getPrincipal() instanceof UserPrincipal principal) {
            // Fresh verification from database to enforce instant offboarding
            Optional<User> freshUserOpt = userRepository.findById(principal.getId());

            if (freshUserOpt.isPresent()) {
                User freshUser = freshUserOpt.get();
                if (freshUser.getStatus() == UserStatus.INACTIVE) {
                    // Instant kill switch
                    String clientIp = request.getHeader("X-Forwarded-For");
                    if (clientIp == null || clientIp.isBlank()) {
                        clientIp = request.getRemoteAddr();
                    }

                    Map<String, Object> details = new HashMap<>();
                    details.put("reason", "Instant Offboarding Perimeter Enforcement: Account is INACTIVE");
                    details.put("uri", request.getRequestURI());
                    details.put("method", request.getMethod());

                    auditLogService.logEvent(
                            freshUser,
                            freshUser.getEmail(),
                            AuditAction.ACCOUNT_INACTIVE_ACCESS_ATTEMPT,
                            null,
                            clientIp,
                            AuditStatus.FAILURE,
                            details
                    );

                    SecurityContextHolder.clearContext();
                    response.setStatus(HttpServletResponse.SC_FORBIDDEN);
                    response.setContentType("application/json");
                    response.getWriter().write("{\"status\":403,\"error\":\"Forbidden\",\"message\":\"Account has been deactivated. Zero-trust access terminated immediately.\"}");
                    return;
                }
            }
        }

        filterChain.doFilter(request, response);
    }
}
