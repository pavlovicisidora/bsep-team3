package rs.ac.uns.ftn.bsep.pki_service.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j; // <-- DODATO
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.multipart.MultipartFile;
import rs.ac.uns.ftn.bsep.pki_service.dto.CreateEeCertificateDto;
import rs.ac.uns.ftn.bsep.pki_service.dto.RejectionDto;
import rs.ac.uns.ftn.bsep.pki_service.model.CertificateData;
import rs.ac.uns.ftn.bsep.pki_service.model.CertificateRequest;
import rs.ac.uns.ftn.bsep.pki_service.model.User;
import rs.ac.uns.ftn.bsep.pki_service.model.enums.RequestStatus;
import rs.ac.uns.ftn.bsep.pki_service.model.enums.UserRole;
import rs.ac.uns.ftn.bsep.pki_service.repository.CertificateRepository;
import rs.ac.uns.ftn.bsep.pki_service.repository.CertificateRequestRepository;

import java.io.IOException;
import java.math.BigInteger;
import java.util.Date;
import java.util.List;

@Service
@RequiredArgsConstructor
@Slf4j // <-- DODATO
public class CertificateRequestService {

    private final CertificateRequestRepository requestRepository;
    private final CertificateService certificateService;
    private final CertificateRepository certificateRepository;

    @Transactional
    public CertificateRequest submitRequest(MultipartFile csrFile, CreateEeCertificateDto dto) throws IOException {
        User currentUser = (User) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        log.info("AUDIT: User '{}' is submitting a new certificate request for issuer serial number: {}", currentUser.getUsername(), dto.getIssuerSerialNumber());

        CertificateRequest newRequest = new CertificateRequest();
        newRequest.setRequester(currentUser);
        newRequest.setStatus(RequestStatus.PENDING);
        newRequest.setCsrPem(new String(csrFile.getBytes()));
        newRequest.setIssuerSerialNumber(new BigInteger(dto.getIssuerSerialNumber()));
        newRequest.setRequestedValidTo(dto.getValidTo());

        CertificateRequest savedRequest = requestRepository.save(newRequest);
        log.info("Successfully saved new certificate request with ID: {}", savedRequest.getId());
        return savedRequest;
    }

    @Transactional
    public List<CertificateRequest> getRequestsForCurrentUser() {
        User currentUser = (User) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        log.info("Fetching all certificate requests for user: {}", currentUser.getUsername());
        return requestRepository.findByRequesterOrderByCreatedAtDesc(currentUser);
    }

    @Transactional(readOnly = true)
    public List<CertificateRequest> getPendingRequests() {
        User currentUser = (User) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        log.info("Fetching pending certificate requests for user: {} with role: {}", currentUser.getUsername(), currentUser.getRole());

        if (currentUser.getRole().equals(UserRole.ADMIN)) {
            return requestRepository.findByStatus(RequestStatus.PENDING);
        } else { // CA_USER
            return requestRepository.findByIssuerOwnerAndStatus(currentUser, RequestStatus.PENDING);
        }
    }

    @Transactional
    public CertificateData approveRequest(Long requestId) {
        User currentUser = (User) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        log.info("AUDIT: User '{}' is attempting to approve certificate request ID: {}", currentUser.getUsername(), requestId);

        CertificateRequest request = requestRepository.findById(requestId)
                .orElseThrow(() -> new IllegalArgumentException("Request not found."));

        if (request.getStatus() != RequestStatus.PENDING) {
            log.warn("Failed to approve request ID: {}. Reason: Request is not in PENDING status, current status is {}", requestId, request.getStatus());
            throw new IllegalStateException("Only PENDING requests can be approved.");
        }

        if (currentUser.getRole().equals(UserRole.CA_USER)) {
            boolean isAuthorized = certificateRepository.isUserOwnerOfIssuerCertificateForRequest(requestId, currentUser);
            if (!isAuthorized) {
                log.warn("SECURITY: User '{}' is not authorized to approve request ID: {} because they do not own the issuer certificate.", currentUser.getUsername(), requestId);
                throw new SecurityException("User is not authorized to approve this request.");
            }
        }

        CreateEeCertificateDto dto = new CreateEeCertificateDto();
        dto.setIssuerSerialNumber(request.getIssuerSerialNumber().toString());
        dto.setValidTo(request.getRequestedValidTo());

        CertificateData newCertificate = certificateService.createEndEntityCertificate(dto, request.getCsrPem(), request.getRequester());

        request.setStatus(RequestStatus.APPROVED);
        requestRepository.save(request);

        log.info("AUDIT: Certificate request ID: {} has been successfully APPROVED by user '{}'. New certificate serial number: {}", requestId, currentUser.getUsername(), newCertificate.getSerialNumber());
        return newCertificate;
    }

    @Transactional
    public CertificateRequest rejectRequest(Long requestId, RejectionDto rejectionDto) {
        User currentUser = (User) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        log.info("AUDIT: User '{}' is attempting to reject certificate request ID: {}", currentUser.getUsername(), requestId);

        CertificateRequest request = requestRepository.findById(requestId)
                .orElseThrow(() -> new IllegalArgumentException("Request not found."));

        if (request.getStatus() != RequestStatus.PENDING) {
            log.warn("Failed to reject request ID: {}. Reason: Request is not in PENDING status, current status is {}", requestId, request.getStatus());
            throw new IllegalStateException("Only PENDING requests can be rejected.");
        }

        if (currentUser.getRole().equals(UserRole.CA_USER)) {
            boolean isAuthorized = certificateRepository.isUserOwnerOfIssuerCertificateForRequest(requestId, currentUser);
            if (!isAuthorized) {
                log.warn("SECURITY: User '{}' is not authorized to reject request ID: {} because they do not own the issuer certificate.", currentUser.getUsername(), requestId);
                throw new SecurityException("User is not authorized to approve this request.");
            }
        }

        request.setStatus(RequestStatus.REJECTED);
        request.setRejectionReason(rejectionDto.getReason());
        CertificateRequest rejectedRequest = requestRepository.save(request);

        log.info("AUDIT: Certificate request ID: {} has been REJECTED by user '{}'. Reason: {}", requestId, currentUser.getUsername(), rejectionDto.getReason());
        return rejectedRequest;
    }
}