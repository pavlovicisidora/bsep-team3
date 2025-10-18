package rs.ac.uns.ftn.bsep.pki_service.dto;

import jakarta.validation.constraints.NotNull;
import lombok.Data;
import org.springframework.web.multipart.MultipartFile;

import java.util.Date;

@Data
public class CertificateRequestDto {

    @NotNull
    private MultipartFile csrFile;

    @NotNull
    private String issuerSerialNumber;

    @NotNull
    private Date validTo;
}
