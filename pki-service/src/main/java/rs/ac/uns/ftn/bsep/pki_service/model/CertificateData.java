package rs.ac.uns.ftn.bsep.pki_service.model;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.math.BigInteger;
import java.util.Date;

import jakarta.persistence.Entity;
import jakarta.persistence.Table;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Entity
@Table(name = "certificates")
@Getter
@Setter
@NoArgsConstructor
public class CertificateData {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, unique = true)
    private BigInteger serialNumber;

    @Column(nullable = false)
    private String subjectDN; // Distinguished Name vlasnika

    @Column(nullable = false)
    private String issuerDN; // Distinguished Name izdavaoca

    @Column(nullable = false)
    private Date validFrom;

    @Column(nullable = false)
    private Date validTo;

    @Column(nullable = false)
    private boolean isCa;

    @Column
    private String alias; // Alias pod kojim je sačuvan u keystore-u

    @Column(nullable = false)
    private boolean isRevoked = false;

    @Column(nullable = false, columnDefinition = "TEXT")
    private String keystorePassword;

}
