package rs.ac.uns.ftn.bsep.pki_service.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import rs.ac.uns.ftn.bsep.pki_service.model.User;

import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Long> {

    Optional<User> findByEmail(String email);

}
