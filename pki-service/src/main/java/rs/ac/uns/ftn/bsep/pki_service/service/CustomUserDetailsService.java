package rs.ac.uns.ftn.bsep.pki_service.service;

import lombok.extern.slf4j.Slf4j; // <-- DODATO
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import rs.ac.uns.ftn.bsep.pki_service.repository.UserRepository;

@Service
@Slf4j // <-- DODATO
public class CustomUserDetailsService implements UserDetailsService {

    private final UserRepository userRepository;

    @Autowired
    public CustomUserDetailsService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        log.info("Attempting to load user details for email: {}", email);

        return userRepository.findByEmail(email)
                .map(user -> {
                    log.info("User found successfully with email: {}", email);
                    return user;
                })
                .orElseThrow(() -> {
                    log.warn("User not found with email: {}", email);
                    return new UsernameNotFoundException("User not found with email: " + email);
                });
    }
}