package com.trustvault.controller;

import com.trustvault.dto.DocumentResponse;
import com.trustvault.entity.User;
import com.trustvault.repository.UserRepository;
import com.trustvault.security.UserPrincipal;
import com.trustvault.service.DocumentService;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.core.io.ByteArrayResource;
import org.springframework.format.annotation.DateTimeFormat;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.time.Instant;
import java.util.Collections;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/documents")
public class DocumentController {

    private final DocumentService documentService;
    private final UserRepository userRepository;

    public DocumentController(DocumentService documentService, UserRepository userRepository) {
        this.documentService = documentService;
        this.userRepository = userRepository;
    }

    private String getClientIp(HttpServletRequest request) {
        String ip = request.getHeader("X-Forwarded-For");
        if (ip == null || ip.isBlank()) {
            ip = request.getRemoteAddr();
        }
        return ip;
    }

    @PostMapping(value = "/upload", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public ResponseEntity<DocumentResponse> uploadDocument(
            @RequestParam("file") MultipartFile file,
            @RequestParam(value = "title", required = false) String title,
            @RequestParam(value = "category", required = false) String category,
            @AuthenticationPrincipal UserPrincipal principal,
            HttpServletRequest request) {

        User user = userRepository.findById(principal.getId())
                .orElseThrow(() -> new IllegalArgumentException("User not found"));

        DocumentResponse resp = documentService.uploadDocument(title, category, file, user, getClientIp(request));
        return ResponseEntity.ok(resp);
    }

    @GetMapping("/{id}")
    public ResponseEntity<DocumentResponse> getDocument(
            @PathVariable("id") String id,
            @AuthenticationPrincipal UserPrincipal principal,
            HttpServletRequest request) {

        User user = userRepository.findById(principal.getId())
                .orElseThrow(() -> new IllegalArgumentException("User not found"));

        DocumentResponse resp = documentService.getDocument(id, user, getClientIp(request));
        return ResponseEntity.ok(resp);
    }

    @GetMapping("/{id}/download")
    public ResponseEntity<ByteArrayResource> downloadDocument(
            @PathVariable("id") String id,
            @RequestParam(value = "passkeyToken", required = false) String passkeyToken,
            @RequestHeader(value = "X-Passkey-Token", required = false) String passkeyHeader,
            @AuthenticationPrincipal UserPrincipal principal,
            HttpServletRequest request) {

        User user = userRepository.findById(principal.getId())
                .orElseThrow(() -> new IllegalArgumentException("User not found"));

        DocumentService.DownloadPayload payload = documentService.downloadDocument(
                id, passkeyToken, passkeyHeader, user, getClientIp(request));

        return ResponseEntity.ok()
                .contentType(MediaType.parseMediaType(payload.getMimeType()))
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"" + payload.getFilename() + "\"")
                .body(new ByteArrayResource(payload.getBytes()));
    }

    @PutMapping("/{id}")
    public ResponseEntity<DocumentResponse> updateDocument(
            @PathVariable("id") String id,
            @RequestBody Map<String, String> body,
            @RequestParam(value = "passkeyToken", required = false) String passkeyParam,
            @RequestHeader(value = "X-Passkey-Token", required = false) String passkeyHeader,
            @AuthenticationPrincipal UserPrincipal principal,
            HttpServletRequest request) {

        User user = userRepository.findById(principal.getId())
                .orElseThrow(() -> new IllegalArgumentException("User not found"));

        String title = body.get("title");
        String category = body.get("category");
        String passkeyToken = passkeyParam != null ? passkeyParam : body.get("passkeyToken");

        DocumentResponse resp = documentService.updateDocument(id, title, category, passkeyToken, passkeyHeader, user, getClientIp(request));
        return ResponseEntity.ok(resp);
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<?> deleteDocument(
            @PathVariable("id") String id,
            @AuthenticationPrincipal UserPrincipal principal,
            HttpServletRequest request) {

        User user = userRepository.findById(principal.getId())
                .orElseThrow(() -> new IllegalArgumentException("User not found"));

        documentService.deleteDocument(id, user, getClientIp(request));
        return ResponseEntity.ok(Collections.singletonMap("message", "Document deleted successfully."));
    }

    @GetMapping
    public ResponseEntity<List<DocumentResponse>> searchDocuments(
            @RequestParam(value = "title", required = false) String title,
            @RequestParam(value = "category", required = false) String category,
            @RequestParam(value = "ownerEmail", required = false) String ownerEmail,
            @RequestParam(value = "startDate", required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) Instant startDate,
            @RequestParam(value = "endDate", required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) Instant endDate,
            @AuthenticationPrincipal UserPrincipal principal) {

        User user = userRepository.findById(principal.getId())
                .orElseThrow(() -> new IllegalArgumentException("User not found"));

        return ResponseEntity.ok(documentService.searchAndFilterDocuments(title, category, ownerEmail, startDate, endDate, user));
    }

    @GetMapping("/owned")
    public ResponseEntity<List<DocumentResponse>> getMyOwnedDocuments(@AuthenticationPrincipal UserPrincipal principal) {
        User user = userRepository.findById(principal.getId())
                .orElseThrow(() -> new IllegalArgumentException("User not found"));

        return ResponseEntity.ok(documentService.getMyOwnedDocuments(user));
    }

    @GetMapping("/shared")
    public ResponseEntity<List<DocumentResponse>> getSharedWithMeDocuments(@AuthenticationPrincipal UserPrincipal principal) {
        User user = userRepository.findById(principal.getId())
                .orElseThrow(() -> new IllegalArgumentException("User not found"));

        return ResponseEntity.ok(documentService.getSharedWithMeDocuments(user));
    }
}
