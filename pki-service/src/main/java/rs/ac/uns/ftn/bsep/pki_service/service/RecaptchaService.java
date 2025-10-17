package rs.ac.uns.ftn.bsep.pki_service.service;

import lombok.extern.slf4j.Slf4j; // <-- DODATO
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestClientException; // <-- DODATO
import org.springframework.web.client.RestTemplate;
import rs.ac.uns.ftn.bsep.pki_service.dto.RecaptchaResponseDto;

@Service
@Slf4j // <-- DODATO
public class RecaptchaService {

    private static final String RECAPTCHA_VERIFY_URL = "https://www.google.com/recaptcha/api/siteverify";

    @Value("${google.recaptcha.secret-key}")
    private String secretKey;

    public boolean validateToken(String token) {
        // Nikada ne logujemo sam token iz bezbednosnih razloga.
        log.info("Attempting to validate reCAPTCHA token with Google's verification service.");
        RestTemplate restTemplate = new RestTemplate();
        String url = RECAPTCHA_VERIFY_URL + "?secret=" + secretKey + "&response=" + token;

        try {
            RecaptchaResponseDto response = restTemplate.postForObject(url, null, RecaptchaResponseDto.class);

            if (response != null && response.isSuccess()) {
                log.info("reCAPTCHA token validation successful.");
                return true;
            } else {
                // Logujemo kao upozorenje jer ovo obično znači da korisnik nije uspešno rešio CAPTCHA.
                // U response objektu se mogu nalaziti i kodovi grešaka, pa je korisno logovati ga.
                log.warn("reCAPTCHA token validation failed. Response from Google: {}", response);
                return false;
            }
        } catch (RestClientException e) {
            // Logujemo kao grešku jer ovo ukazuje na problem u komunikaciji između našeg servera i Google-a
            // (npr. problem sa mrežom, firewall, nedostupnost Google servisa).
            log.error("Error while communicating with reCAPTCHA verification service. Reason: {}", e.getMessage());
            // Ako ne možemo da proverimo, iz bezbednosnih razloga smatramo da validacija nije uspela.
            return false;
        }
    }
}