package rs.ac.uns.ftn.bsep.pki_service.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Date;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class CredentialResponseDto {
    private Long id;
    private String siteName;
    private String username;
    private Date createdAt;
    private String createdByEmail;
}