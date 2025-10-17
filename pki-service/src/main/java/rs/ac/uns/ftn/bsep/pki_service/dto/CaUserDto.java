package rs.ac.uns.ftn.bsep.pki_service.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;


@Getter
@Setter
@AllArgsConstructor
public class CaUserDto {

    private Long id;
    private String firstName;
    private String lastName;
    private String email;

}