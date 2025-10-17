package rs.ac.uns.ftn.bsep.pki_service.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import rs.ac.uns.ftn.bsep.pki_service.model.CertificateRequest;
import rs.ac.uns.ftn.bsep.pki_service.model.User;
import rs.ac.uns.ftn.bsep.pki_service.model.enums.RequestStatus;

import java.util.List;

public interface CertificateRequestRepository extends JpaRepository<CertificateRequest, Long> {
    // Metoda za lako pronalaženje svih zahteva sa određenim statusom
    List<CertificateRequest> findByStatus(RequestStatus status);

    @Query("SELECT cr FROM CertificateRequest cr JOIN CertificateData cd ON cr.issuerSerialNumber = cd.serialNumber WHERE cd.owner = :owner AND cr.status = :status")
    List<CertificateRequest> findByIssuerOwnerAndStatus(@Param("owner") User owner, @Param("status") RequestStatus status);

    /**
     * Pronalazi sve zahteve koje je podneo određeni korisnik.
     * Koristi se da običan korisnik vidi istoriju svojih zahteva.
     */
    List<CertificateRequest> findByRequesterOrderByCreatedAtDesc(User requester);
}