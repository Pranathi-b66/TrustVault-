package com.trustvault.controller;

import com.trustvault.dto.BreakGlassRequest;
import com.trustvault.dto.BreakGlassResponse;
import com.trustvault.security.UserPrincipal;
import com.trustvault.service.BreakGlassService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Break-Glass emergency access control surface.
 *
 * <p>Administrators only, like the rest of {@code /api/admin/**}. The endpoint records the
 * emergency declaration on the WORM trail; opening the document still requires the live face gate
 * and is audited as a separate read.</p>
 */
@RestController
@RequestMapping("/api/admin/break-glass")
@PreAuthorize("hasRole('ADMIN')")
public class BreakGlassController {

    private final BreakGlassService breakGlassService;

    public BreakGlassController(BreakGlassService breakGlassService) {
        this.breakGlassService = breakGlassService;
    }

    private String getClientIp(HttpServletRequest request) {
        String ip = request.getHeader("X-Forwarded-For");
        if (ip == null || ip.isBlank()) {
            ip = request.getRemoteAddr();
        }
        return ip;
    }

    @PostMapping
    public ResponseEntity<BreakGlassResponse> declare(
            @Valid @RequestBody BreakGlassRequest request,
            @AuthenticationPrincipal UserPrincipal principal,
            HttpServletRequest httpRequest) {

        BreakGlassResponse response = breakGlassService.declare(
                request, principal.getId(), getClientIp(httpRequest));
        return ResponseEntity.ok(response);
    }
}
