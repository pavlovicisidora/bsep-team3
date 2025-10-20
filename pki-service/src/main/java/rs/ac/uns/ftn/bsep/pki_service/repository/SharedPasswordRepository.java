package rs.ac.uns.ftn.bsep.pki_service.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import rs.ac.uns.ftn.bsep.pki_service.model.Credential;
import rs.ac.uns.ftn.bsep.pki_service.model.SharedPassword;
import rs.ac.uns.ftn.bsep.pki_service.model.User;

import java.util.List;
import java.util.Optional;

public interface SharedPasswordRepository extends JpaRepository<SharedPassword, Long> {

    List<SharedPassword> findAllByUser(User user);
    Optional<SharedPassword> findByCredentialAndUser(Credential credential, User user);
}
