package rs.ac.uns.ftn.bsep.pki_service.controller;

import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import rs.ac.uns.ftn.bsep.pki_service.dto.LoginRequestDto;
import rs.ac.uns.ftn.bsep.pki_service.dto.LoginResponseDto;
import rs.ac.uns.ftn.bsep.pki_service.dto.PasswordResetRequestDto;
import rs.ac.uns.ftn.bsep.pki_service.dto.UserRegistrationRequestDto;
import rs.ac.uns.ftn.bsep.pki_service.service.UserService;

@RestController
@RequestMapping("/api/auth")
public class AuthenticationController {
    private final UserService userService;

    @Autowired
    public AuthenticationController(UserService userService) {
        this.userService = userService;
    }

    @PostMapping("/register")
    public ResponseEntity<String> registerUser(@Valid @RequestBody UserRegistrationRequestDto registrationDto) {
        userService.registerOrdinaryUser(registrationDto);
        return ResponseEntity.ok("Registration successful. Please check your email to activate your account.");
    }

    @GetMapping("/activate")
    public ResponseEntity<String> activateAccount(@RequestParam("token") String token) {
        userService.activateUser(token);
        return ResponseEntity.ok("Account activated successfully!");
    }

    @PostMapping("/login")
    public ResponseEntity<LoginResponseDto> login(@Valid @RequestBody LoginRequestDto loginDto) {
        LoginResponseDto response = userService.login(loginDto);
        return ResponseEntity.ok(response);
    }

    @PostMapping("/forgot-password")
    public ResponseEntity<String> forgotPassword(@RequestParam("email") String email) {
        userService.initiatePasswordReset(email);
        return ResponseEntity.ok("If an account with that email address exists, we have sent a password reset link.");
    }

    @PostMapping("/reset-password")
    public ResponseEntity<String> resetPassword(@Valid @RequestBody PasswordResetRequestDto resetDto) {
        userService.resetPassword(resetDto); // Menjamo naziv DTO-a ovde
        return ResponseEntity.ok("Password has been reset successfully. You can now log in with your new password.");
    }
}
