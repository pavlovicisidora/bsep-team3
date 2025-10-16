package rs.ac.uns.ftn.bsep.pki_service.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import lombok.Data;

@Data
public class PasswordResetRequestDto {

    @NotEmpty(message = "Token is required.")
    private String token;

    @NotEmpty(message = "New password is required.")
    @Size(min = 8, max = 64, message = "Password must be between 8 and 64 characters long.")
    @Pattern(regexp = "^(?=.*\\d)(?=.*[a-z])(?=.*[A-Z])(?=.*[@#$%^&+=!])(?=\\S+$).*$",
            message = "Password must contain at least one uppercase letter, one lowercase letter, one digit, and one special character.")
    private String newPassword;

    @NotEmpty(message = "Password confirmation is required.")
    private String confirmNewPassword;
}