package rs.ac.uns.ftn.bsep.pki_service.model;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Entity
@Table(name = "templates")
@Getter
@Setter
@NoArgsConstructor
public class Template {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false)
    private String name;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "issuer_certificate_id", nullable = false)
    private CertificateData issuer;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "owner_id", nullable = false)
    private User owner;

    @Column(nullable = false)
    private String commonNameRegex;

    @Column(nullable = true)
    private String subjectAlternativeNamesRegex;

    @Column(nullable = false)
    private Integer timeToLiveDays;

    @Column(nullable = false)
    private String keyUsage; // comma-separated string, npr. "digitalSignature,keyEncipherment"

    @Column(nullable = true)
    private String extendedKeyUsage; // -||-

}
