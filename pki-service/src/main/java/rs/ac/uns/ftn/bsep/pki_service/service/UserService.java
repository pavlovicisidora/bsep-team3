package rs.ac.uns.ftn.bsep.pki_service.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import rs.ac.uns.ftn.bsep.pki_service.dto.UserRegistrationRequestDto;
import rs.ac.uns.ftn.bsep.pki_service.model.User;
import rs.ac.uns.ftn.bsep.pki_service.model.VerificationToken;
import rs.ac.uns.ftn.bsep.pki_service.model.enums.UserRole;
import rs.ac.uns.ftn.bsep.pki_service.repository.UserRepository;
import rs.ac.uns.ftn.bsep.pki_service.repository.VerificationTokenRepository;

import java.util.UUID;

@Service
public class UserService {
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final VerificationTokenRepository tokenRepository;
    private final EmailService emailService;

    @Autowired
    public UserService(UserRepository userRepository, PasswordEncoder passwordEncoder,
                       VerificationTokenRepository tokenRepository, EmailService emailService) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.tokenRepository = tokenRepository;
        this.emailService = emailService;
    }

    public User registerOrdinaryUser(UserRegistrationRequestDto dto) {
        if (!dto.getPassword().equals(dto.getConfirmPassword())) {
            throw new IllegalArgumentException("Passwords do not match.");
        }

        if (userRepository.findByEmail(dto.getEmail()).isPresent()) {
            throw new IllegalArgumentException("Email is already in use.");
        }

        User newUser = new User();
        newUser.setEmail(dto.getEmail());
        newUser.setPassword(passwordEncoder.encode(dto.getPassword()));
        newUser.setFirstName(dto.getFirstName());
        newUser.setLastName(dto.getLastName());
        newUser.setOrganization(dto.getOrganization());
        newUser.setRole(UserRole.ORDINARY_USER);
        newUser.setVerified(false);

        User savedUser = userRepository.save(newUser);
        String tokenString = UUID.randomUUID().toString();
        VerificationToken token = new VerificationToken(tokenString, newUser);
        tokenRepository.save(token);

        emailService.sendActivationEmail(newUser.getEmail(), tokenString);

        return savedUser;
    }

    public void activateUser(String token) {
        VerificationToken verificationToken = tokenRepository.findByToken(token)
                .orElseThrow(() -> new IllegalArgumentException("Invalid activation token."));

        if (verificationToken.isExpired()) {
            tokenRepository.delete(verificationToken);
            throw new IllegalArgumentException("Activation token has expired.");
        }

        User user = verificationToken.getUser();
        user.setVerified(true);
        userRepository.save(user);

        tokenRepository.delete(verificationToken);
    }
}
