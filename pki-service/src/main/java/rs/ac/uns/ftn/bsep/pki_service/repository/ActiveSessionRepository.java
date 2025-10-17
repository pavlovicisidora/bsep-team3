package rs.ac.uns.ftn.bsep.pki_service.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import rs.ac.uns.ftn.bsep.pki_service.model.ActiveSession;
import rs.ac.uns.ftn.bsep.pki_service.model.User;

import java.util.Date;
import java.util.List;
import java.util.Optional;

@Repository
public interface ActiveSessionRepository extends JpaRepository<ActiveSession, String> {
    Optional<ActiveSession> findByJti(String jti);
    List<ActiveSession> findByUser(User user);
    int deleteByExpiresAtBefore(Date now);
}