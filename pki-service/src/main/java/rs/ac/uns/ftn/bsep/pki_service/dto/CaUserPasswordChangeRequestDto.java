package rs.ac.uns.ftn.bsep.pki_service.dto;

import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import lombok.Data;

@Data
public class CaUserPasswordChangeRequestDto {
    @NotEmpty(message = "Current password is required.")
    private String currentPassword;

    @NotEmpty(message = "New password is required.")
    @Size(min = 8, max = 64, message = "Password must be between 8 and 64 characters long.")
    @Pattern(regexp = "^(?=.*[0-9])(?=.*[a-z])(?=.*[A-Z])(?=.*[@#$%^&+=!])(?=\\S+$).*$",
            message = "Password must contain at least one uppercase letter, a lowercase letter, a digit, and a special character.")
    private String newPassword;

    @NotEmpty(message = "Password confirmation is required.")
    private String confirmNewPassword;
}
