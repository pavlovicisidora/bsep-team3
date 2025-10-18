package rs.ac.uns.ftn.bsep.pki_service.dto;

import lombok.Getter;
import lombok.Setter;

import java.util.List;

@Getter
@Setter
public class TemplateCreateDto {
    private String name;
    private String issuerSerialNumber;
    private String commonNameRegex;
    private String subjectAlternativeNamesRegex;
    private Integer timeToLiveDays;
    private List<String> keyUsage;
    private List<String> extendedKeyUsage;
}
