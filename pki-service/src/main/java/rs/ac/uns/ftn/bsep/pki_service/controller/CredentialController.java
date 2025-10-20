package rs.ac.uns.ftn.bsep.pki_service.controller;

import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;
import rs.ac.uns.ftn.bsep.pki_service.dto.*;
import rs.ac.uns.ftn.bsep.pki_service.model.User;
import rs.ac.uns.ftn.bsep.pki_service.service.CredentialService;

import java.nio.file.AccessDeniedException;
import java.util.List;

@RestController
@RequestMapping("/api/credentials")
@RequiredArgsConstructor
public class CredentialController {

    private final CredentialService credentialService;

    @PostMapping
    public ResponseEntity<Void> createCredential(@RequestBody CreateCredentialRequestDto requestDto) {
        credentialService.createCredential(requestDto, getCurrentUser());
        return new ResponseEntity<>(HttpStatus.CREATED);
    }

    @GetMapping
    public ResponseEntity<List<CredentialResponseDto>> getCredentialsForCurrentUser() {
        return ResponseEntity.ok(credentialService.getCredentialsForUser(getCurrentUser()));
    }

    @GetMapping("/{id}/password")
    public ResponseEntity<EncryptedPasswordResponseDto> getEncryptedPassword(@PathVariable Long id) {
        return ResponseEntity.ok(credentialService.getEncryptedPassword(id, getCurrentUser()));
    }

    @PostMapping("/{id}/share")
    public ResponseEntity<Void> shareCredential(@PathVariable Long id, @RequestBody ShareCredentialRequestDto requestDto) throws AccessDeniedException {
        credentialService.shareCredential(id, requestDto, getCurrentUser());
        return ResponseEntity.ok().build();
    }

    private User getCurrentUser() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || !authentication.isAuthenticated()) {
            throw new IllegalStateException("User is not authenticated.");
        }
        return (User) authentication.getPrincipal();
    }
}