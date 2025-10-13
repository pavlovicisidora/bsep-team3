package rs.ac.uns.ftn.bsep.pki_service.service;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;
import rs.ac.uns.ftn.bsep.pki_service.dto.RecaptchaResponseDto;

@Service
public class RecaptchaService {

    private static final String RECAPTCHA_VERIFY_URL = "https://www.google.com/recaptcha/api/siteverify";

    @Value("${google.recaptcha.secret-key}")
    private String secretKey;

    public boolean validateToken(String token) {
        RestTemplate restTemplate = new RestTemplate();
        String url = RECAPTCHA_VERIFY_URL + "?secret=" + secretKey + "&response=" + token;

        RecaptchaResponseDto response = restTemplate.postForObject(url, null, RecaptchaResponseDto.class);

        return response != null && response.isSuccess();
    }
}
