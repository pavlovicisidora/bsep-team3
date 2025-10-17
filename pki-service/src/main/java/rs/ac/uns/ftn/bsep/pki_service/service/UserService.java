package rs.ac.uns.ftn.bsep.pki_service.service;

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

        emailService.sendActivationEmail(newUser.getEmail(), tokenString);

        return savedUser;
    }

    public void createCaUser(CaUserCreateRequestDto dto) {
        if (userRepository.findByEmail(dto.getEmail()).isPresent()) {
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

        emailService.sendCaUserCredentials(newUser.getEmail(), rawPassword);
    }

    private String generateUserSymmetricKey() {
        try {
            // AES ključevi mogu biti 128, 192, ili 256 bita. Koristimo 256 (32 bajta).
            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            keyGen.init(256); // 256 bita
            SecretKey secretKey = keyGen.generateKey();

            // Vraćamo ključ kao Base64 string, jer to čuvamo u bazi
            return Base64.getEncoder().encodeToString(secretKey.getEncoded());
        } catch (NoSuchAlgorithmException e) {
            // Ova greška se u praksi nikada ne bi trebala desiti za "AES"
            throw new RuntimeException("Error generating symmetric key", e);
        }
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

    public LoginResponseDto login(LoginRequestDto dto, HttpServletRequest request) {
        if (!recaptchaService.validateToken(dto.getRecaptchaToken())) {
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
        User user = userRepository.findByEmail(userEmail)
                .orElseThrow(() -> new RuntimeException("User not found!"));

        if (!passwordEncoder.matches(dto.getCurrentPassword(), user.getPassword())) {
            throw new IllegalArgumentException("Incorrect current password.");
        }

        if (!dto.getNewPassword().equals(dto.getConfirmNewPassword())) {
            throw new IllegalArgumentException("New passwords do not match.");
        }

        Strength strength = zxcvbn.measure(dto.getNewPassword());
        if (strength.getScore() < 2) {
            throw new IllegalArgumentException("New password is too weak.");
        }

        user.setPassword(passwordEncoder.encode(dto.getNewPassword()));

        user.setPasswordChangeRequired(false);

        userRepository.save(user);
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

        if (!resetDto.getNewPassword().equals(resetDto.getConfirmNewPassword())) {
            throw new IllegalArgumentException("Passwords do not match.");
        }


        VerificationToken verificationToken = tokenRepository.findByToken(resetDto.getToken())
                .orElseThrow(() -> new IllegalArgumentException("Invalid password reset token."));


        if (verificationToken.isExpired()) {

            tokenRepository.delete(verificationToken);
            throw new IllegalArgumentException("Password reset token has expired.");
        }


        User user = verificationToken.getUser();


        Strength strength = zxcvbn.measure(resetDto.getNewPassword());
        if (strength.getScore() < 2) {
            String feedback = "New password is too weak. " + strength.getFeedback().getWarning();
            throw new IllegalArgumentException(feedback.isEmpty() ? "New password is too weak." : feedback);
        }


        user.setPassword(passwordEncoder.encode(resetDto.getNewPassword()));
        userRepository.save(user);

        tokenRepository.delete(verificationToken);
    }
}
