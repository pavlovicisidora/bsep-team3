package rs.ac.uns.ftn.bsep.pki_service.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import rs.ac.uns.ftn.bsep.pki_service.dto.LoginRequestDto;
import rs.ac.uns.ftn.bsep.pki_service.dto.LoginResponseDto;
import rs.ac.uns.ftn.bsep.pki_service.dto.UserRegistrationRequestDto;
import rs.ac.uns.ftn.bsep.pki_service.model.User;
import rs.ac.uns.ftn.bsep.pki_service.model.VerificationToken;
import rs.ac.uns.ftn.bsep.pki_service.model.enums.UserRole;
import rs.ac.uns.ftn.bsep.pki_service.repository.UserRepository;
import rs.ac.uns.ftn.bsep.pki_service.repository.VerificationTokenRepository;
import com.nulabinc.zxcvbn.Strength;
import com.nulabinc.zxcvbn.Zxcvbn;
import rs.ac.uns.ftn.bsep.pki_service.util.JwtUtil;

import java.util.UUID;

@Service
public class UserService {
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final VerificationTokenRepository tokenRepository;
    private final EmailService emailService;
    private final RecaptchaService recaptchaService;
    private final AuthenticationManager authenticationManager;
    private final JwtUtil jwtUtil;
    private final CustomUserDetailsService customUserDetailsService;

    private final Zxcvbn zxcvbn = new Zxcvbn();

    @Autowired
    public UserService(UserRepository userRepository, PasswordEncoder passwordEncoder,
                       VerificationTokenRepository tokenRepository, EmailService emailService,
                       RecaptchaService recaptchaService, AuthenticationManager authenticationManager,
                       JwtUtil jwtUtil, CustomUserDetailsService customUserDetailsService) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.tokenRepository = tokenRepository;
        this.emailService = emailService;
        this.recaptchaService = recaptchaService;
        this.authenticationManager = authenticationManager;
        this.jwtUtil = jwtUtil;
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

    public LoginResponseDto login(LoginRequestDto dto) {
        if (!recaptchaService.validateToken(dto.getRecaptchaToken())) {
            throw new IllegalArgumentException("reCAPTCHA validation failed.");
        }

        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(dto.getEmail(), dto.getPassword())
        );

        final UserDetails userDetails = this.customUserDetailsService.loadUserByUsername(dto.getEmail());

        User user = (User) userDetails;

        final String token = jwtUtil.generateToken(user);

        return new LoginResponseDto(token);
    }
}
