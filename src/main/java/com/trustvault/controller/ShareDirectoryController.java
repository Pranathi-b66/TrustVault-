package com.trustvault.controller;

import com.trustvault.dto.ShareCandidateResponse;
import com.trustvault.security.UserPrincipal;
import com.trustvault.service.ShareDirectoryService;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

/**
 * Recipient suggestions for the sharing modal.
 *
 * <p>Available to every authenticated vault identity - both {@code OWNER} and {@code VIEWER} share
 * the same baseline and can upload and share what they own. The result is a short, active-only
 * projection; it is not an administrative user listing, which stays behind {@code ROLE_ADMIN}.</p>
 */
@RestController
@RequestMapping("/api/share-candidates")
public class ShareDirectoryController {

    private final ShareDirectoryService shareDirectoryService;

    public ShareDirectoryController(ShareDirectoryService shareDirectoryService) {
        this.shareDirectoryService = shareDirectoryService;
    }

    @GetMapping
    public ResponseEntity<List<ShareCandidateResponse>> suggest(
            @RequestParam(value = "query", required = false) String query,
            @AuthenticationPrincipal UserPrincipal principal) {

        if (principal == null) {
            return ResponseEntity.status(401).build();
        }
        return ResponseEntity.ok(shareDirectoryService.suggest(principal.getId(), query));
    }
}
