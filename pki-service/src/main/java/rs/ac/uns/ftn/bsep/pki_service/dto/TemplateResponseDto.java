package rs.ac.uns.ftn.bsep.pki_service.dto;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class TemplateResponseDto {
    private Long id;
    private String name;
    private String issuerCommonName;
}
