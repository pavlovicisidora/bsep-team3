package rs.ac.uns.ftn.bsep.pki_service.dto;

import lombok.AllArgsConstructor;
import lombok.Data;

import java.util.Date;

@Data
@AllArgsConstructor
public class IssuerDto {
    private String serialNumber;
    private String commonName;
    private String organization;
    private Date validTo;
}
