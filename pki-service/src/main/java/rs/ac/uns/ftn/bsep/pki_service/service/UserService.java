package rs.ac.uns.ftn.bsep.pki_service.service;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import rs.ac.uns.ftn.bsep.pki_service.dto.LoginRequestDto;
import rs.ac.uns.ftn.bsep.pki_service.dto.LoginResponseDto;
import rs.ac.uns.ftn.bsep.pki_service.dto.PasswordResetRequestDto;
import rs.ac.uns.ftn.bsep.pki_service.dto.UserRegistrationRequestDto;
import org.apache.commons.lang3.RandomStringUtils;
import rs.ac.uns.ftn.bsep.pki_service.dto.*;
import rs.ac.uns.ftn.bsep.pki_service.model.User;
import rs.ac.uns.ftn.bsep.pki_service.model.VerificationToken;
import rs.ac.uns.ftn.bsep.pki_service.model.enums.UserRole;
import rs.ac.uns.ftn.bsep.pki_service.repository.UserRepository;
import rs.ac.uns.ftn.bsep.pki_service.repository.VerificationTokenRepository;
import com.nulabinc.zxcvbn.Strength;
import com.nulabinc.zxcvbn.Zxcvbn;
import rs.ac.uns.ftn.bsep.pki_service.util.JwtUtil;
import jakarta.servlet.http.HttpServletRequest;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.stream.Collectors;

@Service
@Slf4j
public class UserService {
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final VerificationTokenRepository tokenRepository;
    private final EmailService emailService;
    private final RecaptchaService recaptchaService;
    private final AuthenticationManager authenticationManager;
    private final JwtUtil jwtUtil;
    private final CustomUserDetailsService customUserDetailsService;
    private final SessionService sessionService;

    private final Zxcvbn zxcvbn = new Zxcvbn();

    @Autowired
    public UserService(UserRepository userRepository, PasswordEncoder passwordEncoder,
                       VerificationTokenRepository tokenRepository, EmailService emailService,
                       RecaptchaService recaptchaService, AuthenticationManager authenticationManager,
                       JwtUtil jwtUtil, CustomUserDetailsService customUserDetailsService, SessionService sessionService) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.tokenRepository = tokenRepository;
        this.emailService = emailService;
        this.recaptchaService = recaptchaService;
        this.authenticationManager = authenticationManager;
        this.jwtUtil = jwtUtil;
        this.sessionService = sessionService;
        this.customUserDetailsService = customUserDetailsService;
    }

    public User registerOrdinaryUser(UserRegistrationRequestDto dto) {
        if (!dto.getPassword().equals(dto.getConfirmPassword())) {
            throw new IllegalArgumentException("Passwords do not match.");
        }

        if (userRepository.findByEmail(dto.getEmail()).isPresent()) {
            throw new IllegalArgumentException("Email is already in use.");
        }

        Strength strength = zxcvbn.measure(dto.getPassword());
        if (strength.getScore() < 2) {
            String feedback = "Password is too weak. " + strength.getFeedback().getWarning();
            throw new IllegalArgumentException(feedback.isEmpty() ? "Password is too weak." : feedback);
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

        log.info("AUDIT: New ordinary user registered successfully with email: {}. Awaiting activation.", savedUser.getEmail());
        emailService.sendActivationEmail(newUser.getEmail(), tokenString);

        return savedUser;
    }

    public void createCaUser(CaUserCreateRequestDto dto) {
        log.info("AUDIT: Admin is attempting to create a new CA user with email: {}", dto.getEmail());
        if (userRepository.findByEmail(dto.getEmail()).isPresent()) {
            log.warn("CA user creation failed: Email {} is already in use.", dto.getEmail());
            throw new IllegalArgumentException("Email is already in use.");
        }

        String rawPassword = RandomStringUtils.randomAlphanumeric(12);

        User newUser = new User();
        newUser.setEmail(dto.getEmail());
        newUser.setPassword(passwordEncoder.encode(rawPassword));
        newUser.setFirstName(dto.getFirstName());
        newUser.setLastName(dto.getLastName());
        newUser.setOrganization(dto.getOrganization());
        newUser.setRole(UserRole.CA_USER);
        newUser.setVerified(true);
        newUser.setPasswordChangeRequired(true);

        String symmetricKey = generateUserSymmetricKey();
        newUser.setUserSymmetricKey(symmetricKey);

        userRepository.save(newUser);
        log.info("AUDIT: New CA user created successfully with email: {}. Sending credentials.", newUser.getEmail());

        emailService.sendCaUserCredentials(newUser.getEmail(), rawPassword);
    }

    private String generateUserSymmetricKey() {
        try {
            log.info("Generating new 256-bit AES symmetric key for a user.");
            // AES ključevi mogu biti 128, 192, ili 256 bita. Koristimo 256 (32 bajta).
            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            keyGen.init(256); // 256 bita
            SecretKey secretKey = keyGen.generateKey();

            // Vraćamo ključ kao Base64 string, jer to čuvamo u bazi
            return Base64.getEncoder().encodeToString(secretKey.getEncoded());
        } catch (NoSuchAlgorithmException e) {
            log.error("CRITICAL: AES algorithm not found while generating symmetric key.", e);
            // Ova greška se u praksi nikada ne bi trebala desiti za "AES"
            throw new RuntimeException("Error generating symmetric key", e);
        }
    }

    public void activateUser(String token) {
        log.info("Attempting to activate user account with a verification token.");
        VerificationToken verificationToken = tokenRepository.findByToken(token)
                .orElseThrow(() -> {
                    log.warn("Account activation failed: Invalid activation token provided.");
                    return new IllegalArgumentException("Invalid activation token.");
                });

        if (verificationToken.isExpired()) {
            log.warn("Account activation failed for user {}: Token has expired.", verificationToken.getUser().getEmail());
            tokenRepository.delete(verificationToken);
            throw new IllegalArgumentException("Activation token has expired.");
        }

        User user = verificationToken.getUser();
        user.setVerified(true);
        userRepository.save(user);
        log.info("AUDIT: User account successfully activated for email: {}", user.getEmail());

        tokenRepository.delete(verificationToken);
    }

    public LoginResponseDto login(LoginRequestDto dto, HttpServletRequest request) {
        if (!recaptchaService.validateToken(dto.getRecaptchaToken())) {
            log.warn("Login failed for user {}: reCAPTCHA validation failed.", dto.getEmail());
            throw new IllegalArgumentException("reCAPTCHA validation failed.");
        }

        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(dto.getEmail(), dto.getPassword())
        );

        final UserDetails userDetails = this.customUserDetailsService.loadUserByUsername(dto.getEmail());

        User user = (User) userDetails;

        final String token = jwtUtil.generateToken(user);
        sessionService.createSession(user, token, request);

        return new LoginResponseDto(token, user.isPasswordChangeRequired());
    }

    public void caUserChangePassword(String userEmail, CaUserPasswordChangeRequestDto dto) {
        log.info("AUDIT: CA user {} is attempting to change their password.", userEmail);
        User user = userRepository.findByEmail(userEmail)
                .orElseThrow(() -> new RuntimeException("User not found!"));

        if (!passwordEncoder.matches(dto.getCurrentPassword(), user.getPassword())) {
            log.warn("Password change failed for user {}: Incorrect current password.", userEmail);
            throw new IllegalArgumentException("Incorrect current password.");
        }

        if (!dto.getNewPassword().equals(dto.getConfirmNewPassword())) {
            log.warn("Password change failed for user {}: New passwords do not match.", userEmail);
            throw new IllegalArgumentException("New passwords do not match.");
        }

        Strength strength = zxcvbn.measure(dto.getNewPassword());
        if (strength.getScore() < 2) {
            log.warn("Password change failed for user {}: New password is too weak.", userEmail);
            throw new IllegalArgumentException("New password is too weak.");
        }

        user.setPassword(passwordEncoder.encode(dto.getNewPassword()));
        user.setPasswordChangeRequired(false);
        userRepository.save(user);
        log.info("AUDIT: CA user {} successfully changed their password.", userEmail);
    }

    public List<CaUserDto> getAllCaUsers() {
        // Dobavljamo sve korisnike sa ulogom CA_USER iz baze
        List<User> caUsers = userRepository.findByRole(UserRole.CA_USER);

        // Mapiramo svakog User-a u CaUserDto, uzimajući samo potrebna polja
        return caUsers.stream()
                .map(user -> new CaUserDto(
                        user.getId(),
                        user.getFirstName(),
                        user.getLastName(),
                        user.getEmail()
                ))
                .collect(Collectors.toList());
    }


    //************ Account Recovery ***************//
    public void initiatePasswordReset(String email) {
        // Logujemo pokušaj bez obzira da li korisnik postoji, da se spreči otkrivanje postojećih email adresa.
        log.info("Password reset process initiated for email: {}", email);
        Optional<User> userOptional = userRepository.findByEmail(email);

        if (userOptional.isPresent()) {
            User user = userOptional.get();
            String tokenString = UUID.randomUUID().toString();
            VerificationToken token = new VerificationToken(tokenString, user);
            tokenRepository.save(token);
            emailService.sendPasswordResetEmail(user.getEmail(), tokenString);
        }
    }


    public void resetPassword(PasswordResetRequestDto resetDto) {
        log.info("Attempting to reset password using a verification token.");
        if (!resetDto.getNewPassword().equals(resetDto.getConfirmNewPassword())) {
            log.warn("Password reset failed: Passwords do not match.");
            throw new IllegalArgumentException("Passwords do not match.");
        }

        VerificationToken verificationToken = tokenRepository.findByToken(resetDto.getToken())
                .orElseThrow(() -> {
                    log.warn("Password reset failed: Invalid password reset token provided.");
                    return new IllegalArgumentException("Invalid password reset token.");
                });

        if (verificationToken.isExpired()) {
            log.warn("Password reset failed for user {}: Token has expired.", verificationToken.getUser().getEmail());
            tokenRepository.delete(verificationToken);
            throw new IllegalArgumentException("Password reset token has expired.");
        }

        User user = verificationToken.getUser();

        Strength strength = zxcvbn.measure(resetDto.getNewPassword());
        if (strength.getScore() < 2) {
            String feedback = "New password is too weak. " + strength.getFeedback().getWarning();
            log.warn("Password reset failed for user {}: New password is too weak.", user.getEmail());
            throw new IllegalArgumentException(feedback.isEmpty() ? "New password is too weak." : feedback);
        }


        user.setPassword(passwordEncoder.encode(resetDto.getNewPassword()));
        userRepository.save(user);
        log.info("AUDIT: Password successfully reset for user: {}", user.getEmail());

        tokenRepository.delete(verificationToken);
    }
}
