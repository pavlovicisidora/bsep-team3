package rs.ac.uns.ftn.bsep.pki_service.model;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import rs.ac.uns.ftn.bsep.pki_service.model.enums.RequestStatus;

import java.math.BigInteger;
import java.util.Date;

@Entity
@Table(name = "certificate_requests")
@Getter
@Setter
@NoArgsConstructor
public class CertificateRequest {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private RequestStatus status;

    @Lob // Large Object - za čuvanje sadržaja CSR fajla
    @Column(nullable = false, columnDefinition = "TEXT")
    private String csrPem; // Čuvamo CSR kao PEM string

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "requester_id", nullable = false)
    private User requester; // Korisnik koji je podneo zahtev

    @Column(nullable = false)
    private BigInteger issuerSerialNumber; // Serijski broj izabranog izdavaoca

    @Column(nullable = false)
    private Date requestedValidTo; // Željeni datum isteka

    @Column
    private String rejectionReason; // Razlog odbijanja, popunjava se po potrebi

    @Column(nullable = false, updatable = false)
    private Date createdAt = new Date();
}
