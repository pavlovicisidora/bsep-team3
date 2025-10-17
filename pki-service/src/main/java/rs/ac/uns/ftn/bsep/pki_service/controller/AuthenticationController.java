package rs.ac.uns.ftn.bsep.pki_service.controller;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.web.bind.annotation.*;
import rs.ac.uns.ftn.bsep.pki_service.dto.LoginRequestDto;
import rs.ac.uns.ftn.bsep.pki_service.dto.LoginResponseDto;
import rs.ac.uns.ftn.bsep.pki_service.dto.PasswordResetRequestDto;
import rs.ac.uns.ftn.bsep.pki_service.dto.UserRegistrationRequestDto;
import rs.ac.uns.ftn.bsep.pki_service.service.UserService;

@RestController
@RequestMapping("/api/auth")
@Slf4j
public class AuthenticationController {
    private final UserService userService;

    @Autowired
    public AuthenticationController(UserService userService) {
        this.userService = userService;
    }

    @PostMapping("/register")
    public ResponseEntity<String> registerUser(@Valid @RequestBody UserRegistrationRequestDto registrationDto) {
        userService.registerOrdinaryUser(registrationDto);
        log.info("AUDIT: New user has succesfully registered and waiting for activation: {}", registrationDto.getEmail());
        return ResponseEntity.ok("Registration successful. Please check your email to activate your account.");
    }

    @GetMapping("/activate")
    public ResponseEntity<String> activateAccount(@RequestParam("token") String token) {
        log.info("AUDIT: Received request to activate account with token.");
        userService.activateUser(token);

        return ResponseEntity.ok("Account activated successfully!");
    }

    @PostMapping("/login")
    public ResponseEntity<LoginResponseDto> login(@Valid @RequestBody LoginRequestDto loginDto, HttpServletRequest request) {
        try {
            LoginResponseDto response = userService.login(loginDto, request);
            log.info("AUDIT: Successful login to the system for the user: {}", loginDto.getEmail());
            return ResponseEntity.ok(response);
        }catch(BadCredentialsException e) {
            // NAKON NEUSPEŠNOG LOGINA (Bitno za bezbednost!):
            log.warn("AUDIT: Unsuccessful login attempt (wrong password) for email: {}", loginDto.getEmail());
            throw e;
        }
    }

    @PostMapping("/forgot-password")
    public ResponseEntity<String> forgotPassword(@RequestParam("email") String email) {
        log.info("AUDIT: Email password change requested: {}", email);
        userService.initiatePasswordReset(email);
        return ResponseEntity.ok("If an account with that email address exists, we have sent a password reset link.");
    }

    @PostMapping("/reset-password")
    public ResponseEntity<String> resetPassword(@Valid @RequestBody PasswordResetRequestDto resetDto) {
        log.info("AUDIT: Password successfully reset with token.");
        userService.resetPassword(resetDto); // Menjamo naziv DTO-a ovde
        return ResponseEntity.ok("Password has been reset successfully. You can now log in with your new password.");
    }
}
