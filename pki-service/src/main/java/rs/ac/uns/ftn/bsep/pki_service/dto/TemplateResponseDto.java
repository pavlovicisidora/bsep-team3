package rs.ac.uns.ftn.bsep.pki_service.dto;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import rs.ac.uns.ftn.bsep.pki_service.model.Template;

@Getter
@Setter
@NoArgsConstructor
public class TemplateResponseDto {
    private Long id;
    private String name;
    private TemplateIssuerDto issuer;
    private String commonNameRegex;
    private String subjectAlternativeNamesRegex;
    private Integer timeToLiveDays;
    private String keyUsage;
    private String extendedKeyUsage;

    public TemplateResponseDto(Template template) {
        this.id = template.getId();
        this.name = template.getName();
        this.issuer = new TemplateIssuerDto(template.getIssuer());
        this.commonNameRegex = template.getCommonNameRegex();
        this.subjectAlternativeNamesRegex = template.getSubjectAlternativeNamesRegex();
        this.timeToLiveDays = template.getTimeToLiveDays();
        this.keyUsage = template.getKeyUsage();
        this.extendedKeyUsage = template.getExtendedKeyUsage();
    }
}