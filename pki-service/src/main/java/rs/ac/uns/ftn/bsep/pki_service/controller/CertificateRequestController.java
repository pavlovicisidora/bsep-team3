package rs.ac.uns.ftn.bsep.pki_service.controller;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;
import rs.ac.uns.ftn.bsep.pki_service.dto.CreateEeCertificateDto;
import rs.ac.uns.ftn.bsep.pki_service.dto.RejectionDto;
import rs.ac.uns.ftn.bsep.pki_service.model.CertificateData;
import rs.ac.uns.ftn.bsep.pki_service.model.CertificateRequest;
import rs.ac.uns.ftn.bsep.pki_service.service.CertificateRequestService;

import java.util.Date;
import java.util.List;

@RestController
@RequestMapping("/api/certificate-requests")
@RequiredArgsConstructor
@Slf4j
public class CertificateRequestController {

    private final CertificateRequestService requestService;

    @PostMapping
    @PreAuthorize("hasRole('ORDINARY_USER')")
    public ResponseEntity<CertificateRequest> submitCertificateRequest(
            @RequestParam("csrFile") MultipartFile csrFile,
            @RequestPart("dto") CreateEeCertificateDto dto) {
        try {
            log.info("AUDIT: Received a request to create an EE certificate.");
            CertificateRequest submittedRequest = requestService.submitRequest(csrFile,dto);
            return new ResponseEntity<>(submittedRequest, HttpStatus.CREATED);
        } catch (Exception e) {
            log.warn("AUDIT: Error while creating the request: {}", e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }

    @GetMapping("/pending")
    @PreAuthorize("hasAnyRole('ADMIN', 'CA_USER')")
    public ResponseEntity<List<CertificateRequest>> getPendingRequests() {
        log.info("AUDIT: Received a request to fetch all pending requests.");
        List<CertificateRequest> requests = requestService.getPendingRequests();
        return ResponseEntity.ok(requests);
    }

    @PostMapping("/{id}/approve")
    @PreAuthorize("hasAnyRole('ADMIN', 'CA_USER')")
    public ResponseEntity<CertificateData> approveRequest(@PathVariable Long id) {
        try {
            log.info("AUDIT: Received a request to approve an EE certificate.");
            CertificateData newCertificate = requestService.approveRequest(id);
            return new ResponseEntity<>(newCertificate, HttpStatus.CREATED);
        } catch (IllegalArgumentException e) {
            log.warn("AUDIT: Error while finding the request with ID: {}", id);
            return ResponseEntity.notFound().build();
        } catch (IllegalStateException e) {
            log.warn("AUDIT: Conflict occurred while approving the request: {}", e.getMessage());
            return ResponseEntity.status(HttpStatus.CONFLICT).build();
        } catch (Exception e) {
            log.warn("AUDIT: An error occurred while approving the request: {}", e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }

    @PostMapping("/{id}/reject")
    @PreAuthorize("hasAnyRole('ADMIN', 'CA_USER')")
    public ResponseEntity<CertificateRequest> rejectRequest(@PathVariable Long id, @RequestBody RejectionDto rejectionDto) {
        try {
            log.info("AUDIT: Received a request to reject an EE certificate.");
            CertificateRequest rejectedRequest = requestService.rejectRequest(id, rejectionDto);
            return ResponseEntity.ok(rejectedRequest);
        } catch (IllegalArgumentException e) {
            log.warn("AUDIT: Error while finding the request with ID: {}", id);
            return ResponseEntity.notFound().build();
        } catch (IllegalStateException e) {
            log.warn("AUDIT: Conflict occurred while rejecting the request: {}", e.getMessage());
            return ResponseEntity.status(HttpStatus.CONFLICT).build();
        }
    }

    @GetMapping("/my-requests")
    @PreAuthorize("hasRole('ORDINARY_USER')")
    public ResponseEntity<List<CertificateRequest>> getMyRequests() {
        log.info("AUDIT: Received a request to fetch all requests of the regular user.");
        List<CertificateRequest> requests = requestService.getRequestsForCurrentUser();
        return ResponseEntity.ok(requests);
    }
}