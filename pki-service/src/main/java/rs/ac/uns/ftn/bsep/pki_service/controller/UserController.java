package rs.ac.uns.ftn.bsep.pki_service.controller;

import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import rs.ac.uns.ftn.bsep.pki_service.dto.CaUserPasswordChangeRequestDto;
import rs.ac.uns.ftn.bsep.pki_service.service.UserService;

import java.security.Principal;

@RestController
@RequestMapping("/api/user")
public class UserController {
    private final UserService userService;

    @Autowired
    public UserController(UserService userService) {
        this.userService = userService;
    }

    @PostMapping("/change-password")
    @PreAuthorize("hasRole('CA_USER')")
    public ResponseEntity<String> caUserChangePassword(
            @Valid @RequestBody CaUserPasswordChangeRequestDto dto,
            Principal principal) {

        userService.caUserChangePassword(principal.getName(), dto);
        return ResponseEntity.ok("Password changed successfully.");
    }
}
