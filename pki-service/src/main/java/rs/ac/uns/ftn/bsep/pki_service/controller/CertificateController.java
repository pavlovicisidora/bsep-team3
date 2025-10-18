package rs.ac.uns.ftn.bsep.pki_service.controller;

import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;
import rs.ac.uns.ftn.bsep.pki_service.dto.*;
import rs.ac.uns.ftn.bsep.pki_service.model.CertificateData;
import rs.ac.uns.ftn.bsep.pki_service.model.User;
import rs.ac.uns.ftn.bsep.pki_service.service.CertificateService;

import java.math.BigInteger;
import java.util.List;

@RestController
@RequestMapping("/api/certificates")
@RequiredArgsConstructor
@Slf4j
public class CertificateController {

    private final CertificateService certificateService;

    @PostMapping("/root")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<?> createRootCertificate(@Valid @RequestBody CreateRootCertificateDto dto ) {
        try {
            log.info("AUDIT: Received a request to create a Root Certificate.");
            CertificateData createdCertificate = certificateService.createRootCertificate(dto);
            return new ResponseEntity<>(createdCertificate, HttpStatus.CREATED);
        } catch (RuntimeException e) {
            log.warn("AUDIT: Failed attempt to create Root certificate: {}", dto.getCommonName());
            return new ResponseEntity<>(e.getMessage(), HttpStatus.BAD_REQUEST);
        }
    }

    @PostMapping("/intermediate")
    @PreAuthorize("hasAnyRole('ADMIN', 'CA_USER')")
    public ResponseEntity<CertificateData> createIntermediateCertificate(@RequestBody CreateIntermediateCertificateDto dto) {
        log.info("AUDIT: Received a request to create an Intermediate Certificate.");
        CertificateData newCertificate = certificateService.createIntermediateCertificate(dto);
        return new ResponseEntity<>(newCertificate, HttpStatus.CREATED);
    }

    @GetMapping("/issuers")
    @PreAuthorize("hasAnyRole('ADMIN', 'CA_USER', 'ORDINARY_USER')")
    public ResponseEntity<List<IssuerDto>> getIssuers() {
        log.info("AUDIT: Received request for obtaining issuer certificates.");
        return ResponseEntity.ok(certificateService.getAvailableIssuers());
    }

    @PostMapping("/end-entity")
    @PreAuthorize("hasAnyRole('ADMIN', 'CA_USER', 'ORDINARY_USER')")
    public ResponseEntity<CertificateData> createEndEntityCertificate(
            @RequestPart("dto") CreateEeCertificateDto dto,
            @RequestPart("csrFile") MultipartFile csrFile) {
        try {
            log.info("AUDIT: Received request for creation of EE Certificate.");
            User currentUser = (User) SecurityContextHolder.getContext().getAuthentication().getPrincipal();

            String csrPem = new String(csrFile.getBytes());
            CertificateData certificate = certificateService.createEndEntityCertificate(dto, csrPem,currentUser);
            return new ResponseEntity<>(certificate, HttpStatus.CREATED);

        } catch (IllegalArgumentException | SecurityException e) {
            log.warn("AUDIT: Incomplete request to create EE certificate: {}", e.getMessage());
            return ResponseEntity.badRequest().build();
        } catch (Exception e) {
            log.warn("AUDIT: Failed attempt to create Root certificate with issuer serial number: {}",dto.getIssuerSerialNumber());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }

    @GetMapping
    @PreAuthorize("hasAnyRole('ADMIN', 'CA_USER', 'ORDINARY_USER')")
    public ResponseEntity<List<CertificateDetailsDto>> getAllCertificates() {
        log.info("AUDIT: Request received for obtaining all certificates.");
        List<CertificateDetailsDto> certificates = certificateService.getAllCertificatesForCurrentUser();
        return ResponseEntity.ok(certificates);
    }

    @PostMapping("/{serialNumber}/revoke")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<String> revokeCertificate(
            @PathVariable BigInteger serialNumber,
            @Valid @RequestBody RevokeCertificateRequestDto dto) {
        try {
            certificateService.revokeCertificate(serialNumber, dto.getReason());
            return ResponseEntity.ok("Certificate (and its chain) revoked successfully.");
        } catch (SecurityException e) {
            return new ResponseEntity<>(e.getMessage(), HttpStatus.FORBIDDEN);
        } catch (IllegalArgumentException e) {
            return new ResponseEntity<>(e.getMessage(), HttpStatus.NOT_FOUND);
        } catch (Exception e) {
            return new ResponseEntity<>("An unexpected error occurred.", HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    @GetMapping(value = "/crl/{issuerAlias}", produces = MediaType.APPLICATION_OCTET_STREAM_VALUE)
    public ResponseEntity<?> getCrl(@PathVariable String issuerAlias) {
        try {
            byte[] crlData = certificateService.generateCrl(issuerAlias);

            HttpHeaders headers = new HttpHeaders();
            headers.add(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=" + issuerAlias + ".crl");

            return ResponseEntity.ok()
                    .headers(headers)
                    .contentType(MediaType.APPLICATION_OCTET_STREAM)
                    .body(crlData);
        } catch (IllegalArgumentException e) {
            return new ResponseEntity<>(e.getMessage(), HttpStatus.NOT_FOUND);
        } catch (Exception e) {
            e.printStackTrace();
            return new ResponseEntity<>("An unexpected error occurred: " + e.getMessage(), HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }


}
