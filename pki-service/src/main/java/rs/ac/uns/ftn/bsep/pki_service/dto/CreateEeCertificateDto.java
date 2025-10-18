package rs.ac.uns.ftn.bsep.pki_service.dto;

import lombok.Data;
import java.util.Date;

@Data
public class CreateEeCertificateDto {
    private String issuerSerialNumber;
    private Date validTo;
    private Long templateId;
}
