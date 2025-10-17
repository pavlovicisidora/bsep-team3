package rs.ac.uns.ftn.bsep.pki_service.controller;

import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;
import rs.ac.uns.ftn.bsep.pki_service.model.ActiveSession;
import rs.ac.uns.ftn.bsep.pki_service.model.User;
import rs.ac.uns.ftn.bsep.pki_service.service.SessionService;

import java.util.List;

@RestController
@RequestMapping("/api/sessions")
@RequiredArgsConstructor
public class SessionController {

    private final SessionService sessionService;

    // Endpoint za dobijanje svih aktivnih sesija za trenutno ulogovanog korisnika
    @GetMapping("/my-sessions")
    @PreAuthorize("hasAnyRole('ADMIN', 'CA_USER', 'ORDINARY_USER')")
    public ResponseEntity<List<ActiveSession>> getMyActiveSessions() {
        // Dobijamo trenutno ulogovanog korisnika
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        User currentUser = (User) authentication.getPrincipal();

        List<ActiveSession> activeSessions = sessionService.findByUser(currentUser);
        return ResponseEntity.ok(activeSessions);
    }

    // Endpoint za opoziv (brisanje) određene sesije
    // Korisnik može obrisati samo svoju sesiju
    @DeleteMapping("/{jti}")
    @PreAuthorize("hasAnyRole('ADMIN', 'CA_USER', 'ORDINARY_USER')")
    public ResponseEntity<Void> revokeSession(@PathVariable String jti) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        User currentUser = (User) authentication.getPrincipal();

        // Proveravamo da li sesija pripada trenutnom korisniku pre brisanja
        sessionService.findById(jti).ifPresent(session -> {
            if (session.getUser().getId().equals(currentUser.getId())) {
                sessionService.revokeSession(jti);
            } else {
                // Možete baciti izuzetak ako korisnik pokuša obrisati tuđu sesiju
                // npr. throw new ForbiddenException("You can only revoke your own sessions.");
            }
        });

        return ResponseEntity.noContent().build();
    }

    @DeleteMapping("/logout")
    @ResponseStatus(HttpStatus.NO_CONTENT) // Vraća uspešan status bez tela
    public void logout(HttpServletRequest request) {
        // Prosleđujemo ceo "Authorization" heder servisu
        String authHeader = request.getHeader("Authorization");
        sessionService.revokeSessionByToken(authHeader);
    }
}