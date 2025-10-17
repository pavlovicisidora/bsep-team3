package rs.ac.uns.ftn.bsep.pki_service.dto;

import jakarta.validation.constraints.NotNull;
import lombok.Data;
import rs.ac.uns.ftn.bsep.pki_service.model.enums.RevocationReason;

@Data
public class RevokeCertificateRequestDto {
    @NotNull(message = "Revocation reason is required.")
    private RevocationReason reason;
}
