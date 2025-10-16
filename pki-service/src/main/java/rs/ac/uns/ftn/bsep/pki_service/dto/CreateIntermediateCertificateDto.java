package rs.ac.uns.ftn.bsep.pki_service.dto;

import jakarta.validation.constraints.Future;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

import lombok.Getter;
import lombok.Setter;

import java.util.Date;

@Getter
@Setter
public class CreateIntermediateCertificateDto {

    @NotBlank(message = "Common Name is required.")
    private String commonName;

    @NotBlank(message = "Organization is required.")
    private String organization;

    @NotBlank(message = "Organizational Unit is required.")
    private String organizationalUnit;

    @NotBlank(message = "Country code is required.")
    private String country;

    @NotBlank(message = "Email is required.")
    private String email; // E

    // Podaci o validnosti sertifikata
    @NotNull(message = "Start date is required.")
    private Date validFrom;

    @NotNull(message = "End date is required.")
    @Future(message = "End date must be in the future.")
    private Date validTo;

    @NotNull(message = "Serial number/allias of parent certificate is required.")
    private String issuerSerialNumber;

    @NotNull(message = "Certificate OwnerId is required.")
    private Long ownerId;
}
