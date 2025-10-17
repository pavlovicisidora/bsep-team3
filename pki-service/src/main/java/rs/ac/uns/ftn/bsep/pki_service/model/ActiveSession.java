package rs.ac.uns.ftn.bsep.pki_service.model;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.Date;

@Entity
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class ActiveSession {

    @Id
    @Column(length = 36) // UUID je 36 karaktera
    private String jti; // JWT ID, ovo je primarni ključ

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    @Column(nullable = false)
    private String ipAddress;

    @Column(columnDefinition = "TEXT")
    private String userAgent; // Podaci o browseru i OS-u

    @Temporal(TemporalType.TIMESTAMP)
    @Column(nullable = false)
    private Date lastActivity;

    @Temporal(TemporalType.TIMESTAMP)
    @Column(nullable = false)
    private Date expiresAt;


}