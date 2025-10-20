package rs.ac.uns.ftn.bsep.pki_service.dto;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import rs.ac.uns.ftn.bsep.pki_service.model.CertificateData;

@Getter
@Setter
@NoArgsConstructor
public class TemplateIssuerDto {

    private String serialNumber;
    private String subjectDN;

    public TemplateIssuerDto(CertificateData issuerEntity) {
        if (issuerEntity != null) {
            this.serialNumber = issuerEntity.getSerialNumber().toString();
            this.subjectDN = issuerEntity.getSubjectDN();
        }
    }
}