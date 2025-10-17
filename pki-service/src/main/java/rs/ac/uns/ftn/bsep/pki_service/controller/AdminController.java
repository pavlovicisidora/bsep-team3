package rs.ac.uns.ftn.bsep.pki_service.controller;

import jakarta.validation.Valid;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import rs.ac.uns.ftn.bsep.pki_service.dto.CaUserCreateRequestDto;
import rs.ac.uns.ftn.bsep.pki_service.service.UserService;

@RestController
@PreAuthorize("hasRole('ADMIN')")
@RequestMapping("/api/admin")
@Slf4j
public class AdminController {
    private final UserService userService;

    @Autowired
    public AdminController(UserService userService) {
        this.userService = userService;
    }

    @PostMapping("/ca-user")
    public ResponseEntity<String> createCaUser(@Valid @RequestBody CaUserCreateRequestDto dto) {
        log.info("AUDIT: Admin trying to create new CA user.");
        userService.createCaUser(dto);
        return ResponseEntity.status(HttpStatus.CREATED).body("CA user created successfully. Credentials have been sent to their email.");
    }
}
