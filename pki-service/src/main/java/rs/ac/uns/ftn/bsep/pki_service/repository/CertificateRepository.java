package rs.ac.uns.ftn.bsep.pki_service.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import rs.ac.uns.ftn.bsep.pki_service.model.CertificateData;
import rs.ac.uns.ftn.bsep.pki_service.model.User;

import java.math.BigInteger;
import java.util.Date;
import java.util.List;
import java.util.Optional;

public interface CertificateRepository extends JpaRepository<CertificateData, Long> {

    List<CertificateData> findByOwner(User owner);

    List<CertificateData> findByOwnerAndIsCaFalse(User owner);

    Optional<CertificateData> findBySerialNumber(BigInteger serialNumber);

    /**
     * Pronalazi sve sertifikate koji su CA (isCa = true) i koji nisu povučeni (isRevoked = false).
     * Koristi se da prikaže Adminu sve dostupne izdavaoce u sistemu.
     */
    List<CertificateData> findByIsCaTrueAndIsRevokedFalse();

    /**
     * Pronalazi sve sertifikate koji su CA, nisu povučeni i pripadaju određenom korisniku (owner).
     * Koristi se da prikaže CA korisniku samo one izdavaoce koje on sme da koristi.
     * @param owner Korisnikov id čije sertifikate tražimo.
     */
    List<CertificateData> findByIsCaTrueAndIsRevokedFalseAndOwner(User owner);

    /**
     * Pronalazi sve sertifikate koji su CA (isCa = true) i koji nisu povučeni (isRevoked = false).
     * Koristi se da prikaže pokaže običnom useru koji su trenutno validni sertifikati za njrgov EE sertifikat
     */
    List<CertificateData> findByIsCaTrueAndIsRevokedFalseAndValidFromBeforeAndValidToAfter(Date nowForFrom, Date nowForTo);

    @Query("SELECT COUNT(cr) > 0 " +
            "FROM CertificateRequest cr " +
            "JOIN CertificateData cd ON cr.issuerSerialNumber = cd.serialNumber " +
            "WHERE cr.id = :requestId AND cd.owner = :owner")
    boolean isUserOwnerOfIssuerCertificateForRequest(@Param("requestId") Long requestId, @Param("owner") User owner);
}
