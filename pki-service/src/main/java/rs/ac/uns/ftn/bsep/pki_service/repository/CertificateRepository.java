package rs.ac.uns.ftn.bsep.pki_service.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import rs.ac.uns.ftn.bsep.pki_service.model.CertificateData;
import rs.ac.uns.ftn.bsep.pki_service.model.User;

import java.math.BigInteger;
import java.util.List;
import java.util.Optional;

public interface CertificateRepository extends JpaRepository<CertificateData, Long> {
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
     * @return Lista sertifikata koji zadovoljavaju kriterijume.
     */
    List<CertificateData> findByIsCaTrueAndIsRevokedFalseAndOwner(User owner);

    List<CertificateData> findByIssuerDN(String issuerDN);
    List<CertificateData> findByIssuerDNAndIsRevokedTrue(String issuerDN);
}
