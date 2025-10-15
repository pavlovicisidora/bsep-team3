package rs.ac.uns.ftn.bsep.pki_service.service;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

@Service
public class KeystoreService {

    @Value("${keystore.path}")
    private String keystorePath;

    public void saveCertificate(X509Certificate certificate, PrivateKey privateKey, String alias, String entryPassword) {
        try {
            KeyStore keyStore = KeyStore.getInstance("JKS");

            char[] keystorePassword = new char[0];

            // Učitaj keystore sa null lozinkom, jer sam fajl nema lozinku, već samo unosi (entries)
            try (FileInputStream fis = new FileInputStream(keystorePath)) {
                keyStore.load(fis, null);
            } catch (Exception e) {
                keyStore.load(null, null);
            }

            X509Certificate[] certificateChain = {certificate};
            // Koristimo prosleđenu lozinku za zaštitu privatnog ključa
            keyStore.setKeyEntry(alias, privateKey, entryPassword.toCharArray(), certificateChain);

            // Čuvamo keystore bez globalne lozinke
            try (FileOutputStream fos = new FileOutputStream(keystorePath)) {
                keyStore.store(fos, keystorePassword);
            }

        } catch (Exception e) {
            throw new RuntimeException("Error while saving certificate to keystore", e);
        }
    }

}
