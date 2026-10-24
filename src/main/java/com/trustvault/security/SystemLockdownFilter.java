package com.trustvault.security;

import com.trustvault.entity.Role;
import com.trustvault.service.SystemLockdownService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.time.Instant;

/**
 * Global perimeter for the Emergency Kill Switch.
 *
 * <p>Runs after JWT authentication and the per-user offboarding check, but before Spring
 * Security's authorization filter, so it applies to every request regardless of endpoint:</p>
 *
 * <ul>
 *   <li>Static assets and {@code POST /api/auth/login} stay reachable so the SPA can load and an
 *       administrator can authenticate during the incident.</li>
 *   <li>Administrators keep {@code /api/admin/**} (plus {@code /api/auth/me}) so they can drive
 *       the incident console and lift the lockdown.</li>
 *   <li>Everyone else - and every document operation, including those issued by an administrator -
 *       is rejected with {@code 503 Service Unavailable} and the fixed lockdown message. The
 *       stored reason is never leaked to callers.</li>
 * </ul>
 */
@Component
public class SystemLockdownFilter extends OncePerRequestFilter {

    public static final String LOCKDOWN_MESSAGE = "System is under administrative security lockdown";

    private final SystemLockdownService systemLockdownService;

    public SystemLockdownFilter(SystemLockdownService systemLockdownService) {
        this.systemLockdownService = systemLockdownService;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        if (!systemLockdownService.isLockdownEnabled()) {
            filterChain.doFilter(request, response);
            return;
        }

        String path = resolvePath(request);

        // The login surface must stay open: without it an administrator cannot obtain the token
        // that the lockdown itself relies on.
        if (isStaticSurface(path) || "/api/auth/login".equals(path)) {
            filterChain.doFilter(request, response);
            return;
        }

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        boolean administrator = isAdministrator(authentication);

        // Admins keep the incident console; document operations are frozen for everyone so no
        // evidence can be altered while the lockdown is active.
        if (administrator && isAdministratorSurface(path)) {
            filterChain.doFilter(request, response);
            return;
        }

        logger.debug("Lockdown rejected " + request.getMethod() + " " + path + " (admin=" + administrator + ")");
        writeLockdownResponse(response);
    }

    private String resolvePath(HttpServletRequest request) {
        String uri = request.getRequestURI();
        String contextPath = request.getContextPath();
        if (contextPath != null && !contextPath.isEmpty() && uri.startsWith(contextPath)) {
            return uri.substring(contextPath.length());
        }
        return uri;
    }

    private boolean isStaticSurface(String path) {
        return "/".equals(path)
                || "/index.html".equals(path)
                || "/error".equals(path)
                || path.startsWith("/css/")
                || path.startsWith("/js/")
                || path.startsWith("/favicon");
    }

    private boolean isAdministratorSurface(String path) {
        return "/api/admin".equals(path)
                || path.startsWith("/api/admin/")
                || "/api/auth/me".equals(path);
    }

    private boolean isAdministrator(Authentication authentication) {
        if (authentication == null || !authentication.isAuthenticated()) {
            return false;
        }
        if (authentication.getPrincipal() instanceof UserPrincipal principal) {
            return principal.getRole() == Role.ADMIN;
        }
        for (GrantedAuthority authority : authentication.getAuthorities()) {
            if ("ROLE_ADMIN".equals(authority.getAuthority())) {
                return true;
            }
        }
        return false;
    }

    private void writeLockdownResponse(HttpServletResponse response) throws IOException {
        response.setStatus(HttpServletResponse.SC_SERVICE_UNAVAILABLE);
        response.setContentType("application/json");
        response.setCharacterEncoding("UTF-8");
        response.setHeader("Cache-Control", "no-store");
        response.setHeader("Retry-After", "30");
        response.getWriter().write("{"
                + "\"timestamp\":\"" + Instant.now() + "\","
                + "\"status\":503,"
                + "\"error\":\"Service Unavailable\","
                + "\"code\":\"SYSTEM_LOCKDOWN\","
                + "\"message\":\"" + LOCKDOWN_MESSAGE + "\""
                + "}");
    }
}
