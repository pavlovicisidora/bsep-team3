package rs.ac.uns.ftn.bsep.pki_service.service;

import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;

@Service
@Slf4j
public class EncryptionService {

    private static final String ALGORITHM = "AES/CBC/PKCS5Padding";

    public String encrypt(String plainText, String base64UserKey) {
        log.info("Starting encryption process.");
        try {
            byte[] userKeyBytes = Base64.getDecoder().decode(base64UserKey);
            byte[] iv = new byte[16];
            System.arraycopy(userKeyBytes, 0, iv, 0, 16);
            SecretKeySpec secretKey = new SecretKeySpec(userKeyBytes, "AES");
            IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);

            Cipher cipher = Cipher.getInstance(ALGORITHM);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivParameterSpec);
            byte[] encryptedBytes = cipher.doFinal(plainText.getBytes());
            String encryptedString = Base64.getEncoder().encodeToString(encryptedBytes);
            log.info("Encryption process completed successfully.");
            return encryptedString;
        } catch (Exception e) {
            // Logovanje kritične greške. Ako enkripcija ne uspe, sistem ne može da sačuva poverljive podatke.
            log.error("CRITICAL: Error during encryption. Reason: {}", e.getMessage(), e);
            throw new RuntimeException("Error encrypting data", e);
        }
    }

    public String decrypt(String encryptedText, String base64UserKey) {
        log.info("Starting decryption process.");
        try {
            byte[] userKeyBytes = Base64.getDecoder().decode(base64UserKey);
            byte[] iv = new byte[16];
            System.arraycopy(userKeyBytes, 0, iv, 0, 16);
            SecretKeySpec secretKey = new SecretKeySpec(userKeyBytes, "AES");
            IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);

            Cipher cipher = Cipher.getInstance(ALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE, secretKey, ivParameterSpec);
            byte[] decodedBytes = Base64.getDecoder().decode(encryptedText);
            byte[] decryptedBytes = cipher.doFinal(decodedBytes);
            String decryptedString = new String(decryptedBytes);
            log.info("Decryption process completed successfully.");
            return decryptedString;
        } catch (Exception e) {
            // Logovanje kritične greške. Ako dekripcija ne uspe, korisnik ne može da pristupi svojim podacima (npr. privatnom ključu).
            log.error("CRITICAL: Error during decryption. Reason: {}", e.getMessage(), e);
            throw new RuntimeException("Error decrypting data", e);
        }
    }
}