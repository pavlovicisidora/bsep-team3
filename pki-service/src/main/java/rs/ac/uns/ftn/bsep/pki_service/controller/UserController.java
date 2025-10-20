package rs.ac.uns.ftn.bsep.pki_service.controller;

import jakarta.validation.Valid;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;
import rs.ac.uns.ftn.bsep.pki_service.dto.CaUserDto;
import rs.ac.uns.ftn.bsep.pki_service.dto.CaUserPasswordChangeRequestDto;
import rs.ac.uns.ftn.bsep.pki_service.dto.UserPublicKeyDto;
import rs.ac.uns.ftn.bsep.pki_service.service.UserService;

import java.security.Principal;
import java.util.List;

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

    @GetMapping("/ca-users")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<List<CaUserDto>> getCaUsers() {
        List<CaUserDto> caUsers = userService.getAllCaUsers();
        return ResponseEntity.ok(caUsers);
    }

    @GetMapping("/me/public-key")// Bilo koji ulogovani korisnik može pristupiti
    public ResponseEntity<UserPublicKeyDto> getCurrentUserPublicKey(Principal principal) {
        UserPublicKeyDto publicKeyDto = userService.getPublicKeyForUser(principal.getName());
        return ResponseEntity.ok(publicKeyDto);
    }

    @GetMapping("/email/{email}/public-key")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<UserPublicKeyDto> getPublicKeyByEmail(@PathVariable String email) {
        UserPublicKeyDto publicKeyDto = userService.getPublicKeyForUser(email);
        return ResponseEntity.ok(publicKeyDto);
    }
}
