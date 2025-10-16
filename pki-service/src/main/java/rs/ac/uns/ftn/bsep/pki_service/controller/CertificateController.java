package rs.ac.uns.ftn.bsep.pki_service.controller;

import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;
import rs.ac.uns.ftn.bsep.pki_service.dto.*;
import rs.ac.uns.ftn.bsep.pki_service.model.CertificateData;
import rs.ac.uns.ftn.bsep.pki_service.service.CertificateService;

import java.math.BigInteger;
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
    public ResponseEntity<byte[]> getCrl(@PathVariable String issuerAlias) {
        try {
            byte[] crlData = certificateService.generateCrl(issuerAlias);

            HttpHeaders headers = new HttpHeaders();
            headers.add(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=" + issuerAlias + ".crl");

            return ResponseEntity.ok()
                    .headers(headers)
                    .contentType(MediaType.APPLICATION_OCTET_STREAM)
                    .body(crlData);
        } catch (IllegalArgumentException e) {
            return ResponseEntity.notFound().build();
        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }


}
