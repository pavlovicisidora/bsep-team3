package rs.ac.uns.ftn.bsep.pki_service.service;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import jakarta.annotation.PostConstruct;
import java.util.Base64;

@Service
public class EncryptionService {


    private static final String ALGORITHM = "AES/CBC/PKCS5Padding";

    // METODA JE PROMENJENA: Sada prima ključ korisnika kao argument
    public String encrypt(String plainText, String base64UserKey) {
        try {
            // Logika koja je bila u init() se sada izvršava ovde, sa ključem korisnika
            byte[] userKeyBytes = Base64.getDecoder().decode(base64UserKey);
            byte[] iv = new byte[16];
            System.arraycopy(userKeyBytes, 0, iv, 0, 16);
            SecretKeySpec secretKey = new SecretKeySpec(userKeyBytes, "AES");
            IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);

            Cipher cipher = Cipher.getInstance(ALGORITHM);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivParameterSpec);
            byte[] encryptedBytes = cipher.doFinal(plainText.getBytes());
            return Base64.getEncoder().encodeToString(encryptedBytes);
        } catch (Exception e) {
            throw new RuntimeException("Error encrypting data", e);
        }
    }

    // METODA JE PROMENJENA: I ona prima ključ korisnika kao argument
    public String decrypt(String encryptedText, String base64UserKey) {
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
            return new String(decryptedBytes);
        } catch (Exception e) {
            throw new RuntimeException("Error decrypting data", e);
        }
    }
}