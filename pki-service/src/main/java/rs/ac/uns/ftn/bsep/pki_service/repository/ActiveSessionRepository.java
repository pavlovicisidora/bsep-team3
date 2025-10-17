package rs.ac.uns.ftn.bsep.pki_service.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import rs.ac.uns.ftn.bsep.pki_service.model.ActiveSession;
import rs.ac.uns.ftn.bsep.pki_service.model.User;
import org.springframework.data.jpa.repository.Modifying; // <<--- 1. DODAJTE IMPORT
import org.springframework.data.jpa.repository.Query; // <<--- 2. DODAJTE IMPORT
import org.springframework.data.repository.query.Param; // <<--- 3. DODAJTE IMPORT

import java.util.Date;
import java.util.List;
import java.util.Optional;

@Repository
public interface ActiveSessionRepository extends JpaRepository<ActiveSession, String> {
    Optional<ActiveSession> findByJti(String jti);
    List<ActiveSession> findByUser(User user);
    @Modifying
    @Query("DELETE FROM ActiveSession s WHERE s.expiresAt < :now")
    int deleteExpiredSessions(@Param("now") Date now);
}