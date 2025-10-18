package rs.ac.uns.ftn.bsep.pki_service.dto;


import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import rs.ac.uns.ftn.bsep.pki_service.model.enums.RevocationReason;

import java.util.Date;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class CertificateDetailsDto {

    private String serialNumber;
    private String commonName;
    private String issuerCommonName;
    private Date validFrom;
    private Date validTo;
    private boolean isCa;
    private boolean isRevoked;
    private RevocationReason revocationReason;
    private String ownerUsername;
    private String alias;
}
