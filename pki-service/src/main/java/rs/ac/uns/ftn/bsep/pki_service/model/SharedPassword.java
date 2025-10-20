package rs.ac.uns.ftn.bsep.pki_service.model;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.Date;

@Entity
@Table(name = "shared_passwords")
@Getter
@Setter
@NoArgsConstructor
public class SharedPassword {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "credential_id", nullable = false)
    private Credential credential;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    @Column(name = "encrypted_password", nullable = false, columnDefinition = "TEXT")
    private String encryptedPassword;


    @Temporal(TemporalType.TIMESTAMP)
    @Column(name = "created_at", nullable = false, updatable = false)
    private Date createdAt;


    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "created_by_user_id", nullable = false)
    private User createdBy;

    @PrePersist
    protected void onCreate() {
        this.createdAt = new Date();
    }
}