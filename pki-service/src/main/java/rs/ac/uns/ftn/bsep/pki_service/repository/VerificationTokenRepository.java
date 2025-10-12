package rs.ac.uns.ftn.bsep.pki_service.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import rs.ac.uns.ftn.bsep.pki_service.model.VerificationToken;

import java.util.Optional;

public interface VerificationTokenRepository extends JpaRepository<VerificationToken, Long> {
    Optional<VerificationToken> findByToken(String token);
}
