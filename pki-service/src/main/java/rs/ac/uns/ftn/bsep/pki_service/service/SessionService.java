package rs.ac.uns.ftn.bsep.pki_service.service;

import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import rs.ac.uns.ftn.bsep.pki_service.model.ActiveSession;
import rs.ac.uns.ftn.bsep.pki_service.model.User;
import rs.ac.uns.ftn.bsep.pki_service.repository.ActiveSessionRepository;
import rs.ac.uns.ftn.bsep.pki_service.util.JwtUtil;

import java.util.Date;
import java.util.List;
import java.util.Optional;

@Service
@RequiredArgsConstructor
public class SessionService {
    private final ActiveSessionRepository sessionRepository;
    private final JwtUtil jwtUtil;

    public void createSession(User user, String token, HttpServletRequest request) {
        String jti = jwtUtil.extractJti(token);
        String ipAddress = request.getRemoteAddr();
        String userAgent = request.getHeader("User-Agent");
        Date lastActivity = new Date();
        Date expiresAt = jwtUtil.extractExpiration(token);


        ActiveSession session = new ActiveSession(jti, user, ipAddress, userAgent, lastActivity, expiresAt);
        sessionRepository.save(session);
    }

    public Optional<ActiveSession> findById(String jti) {
        return sessionRepository.findByJti(jti);
    }

    public List<ActiveSession> findByUser(User user) {
        return sessionRepository.findByUser(user);
    }

    public void revokeSession(String jti) {
        sessionRepository.deleteById(jti);
    }

    public void updateLastActivity(String jti) {
        sessionRepository.findByJti(jti).ifPresent(session -> {
            session.setLastActivity(new Date());
            sessionRepository.save(session);
        });
    }

    public void revokeSessionByToken(String authHeader) {
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            return;
        }

        try {
            String jwt = authHeader.substring(7);
            String jti = jwtUtil.extractJti(jwt);
            sessionRepository.deleteById(jti);
            System.out.println("Uspešno obrisana sesija sa JTI: " + jti);
        } catch (Exception e) {

            System.err.println("Greška pri brisanju sesije iz tokena: " + e.getMessage());
        }
    }
}
