package rs.ac.uns.ftn.bsep.pki_service.dto;

import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class LoginResponseDto {
    private String jwt;
}
