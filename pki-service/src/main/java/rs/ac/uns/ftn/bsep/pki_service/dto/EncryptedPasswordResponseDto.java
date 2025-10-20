package rs.ac.uns.ftn.bsep.pki_service.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class EncryptedPasswordResponseDto {
    private String encryptedPassword;
}