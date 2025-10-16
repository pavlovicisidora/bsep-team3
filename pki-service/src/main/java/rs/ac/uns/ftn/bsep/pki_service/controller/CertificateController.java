package rs.ac.uns.ftn.bsep.pki_service.controller;

import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;
import rs.ac.uns.ftn.bsep.pki_service.dto.CreateEeCertificateDto;
import rs.ac.uns.ftn.bsep.pki_service.dto.CreateIntermediateCertificateDto;
import rs.ac.uns.ftn.bsep.pki_service.dto.CreateRootCertificateDto;
import rs.ac.uns.ftn.bsep.pki_service.dto.IssuerDto;
import rs.ac.uns.ftn.bsep.pki_service.model.CertificateData;
import rs.ac.uns.ftn.bsep.pki_service.service.CertificateService;

import java.util.List;

@RestController
@RequestMapping("/api/certificates")
@RequiredArgsConstructor
public class CertificateController {

    private final CertificateService certificateService;

    @PostMapping("/root")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<?> createRootCertificate(@Valid @RequestBody CreateRootCertificateDto dto ) {
        try {
            CertificateData createdCertificate = certificateService.createRootCertificate(dto);
            return new ResponseEntity<>(createdCertificate, HttpStatus.CREATED);
        } catch (RuntimeException e) {

            return new ResponseEntity<>(e.getMessage(), HttpStatus.BAD_REQUEST);
        }
    }

    @PostMapping("/intermediate")
    @PreAuthorize("hasAnyRole('ADMIN', 'CA_USER')")
    public ResponseEntity<CertificateData> createIntermediateCertificate(@RequestBody CreateIntermediateCertificateDto dto) {
        CertificateData newCertificate = certificateService.createIntermediateCertificate(dto);
        return new ResponseEntity<>(newCertificate, HttpStatus.CREATED);
    }

    @GetMapping("/issuers")
    @PreAuthorize("hasAnyRole('ADMIN', 'CA_USER')")
    public ResponseEntity<List<IssuerDto>> getIssuers() {
        return ResponseEntity.ok(certificateService.getAvailableIssuers());
    }

    @PostMapping("/end-entity")
    @PreAuthorize("hasAnyRole('ADMIN', 'CA_USER')")
    public ResponseEntity<CertificateData> createEndEntityCertificate(
            @RequestPart("dto") CreateEeCertificateDto dto,
            @RequestPart("csrFile") MultipartFile csrFile) {
        try {
            CertificateData certificate = certificateService.createEndEntityCertificate(dto, csrFile);
            return new ResponseEntity<>(certificate, HttpStatus.CREATED);
        } catch (IllegalArgumentException | SecurityException e) {
            return ResponseEntity.badRequest().build();
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }


}
