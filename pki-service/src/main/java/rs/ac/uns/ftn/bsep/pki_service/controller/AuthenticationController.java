package rs.ac.uns.ftn.bsep.pki_service.controller;

import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
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
}
