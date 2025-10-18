package rs.ac.uns.ftn.bsep.pki_service.service;

import lombok.extern.slf4j.Slf4j; // <-- DODATO
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

@Service
@Slf4j // <-- DODATO
public class KeystoreService {

    @Value("${keystore.path}")
    private String keystorePath;

    private KeyStore loadKeyStore() throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException {
        KeyStore keyStore = KeyStore.getInstance("JKS");
        try (FileInputStream fis = new FileInputStream(keystorePath)) {
            keyStore.load(fis, new char[0]); // Lozinka za keystore fajl
            log.info("Successfully loaded keystore from path: {}", keystorePath);
        } catch (IOException e) {
            log.warn("Keystore file not found at path: {}. A new keystore will be created in memory.", keystorePath);
            keyStore.load(null, null);
        }
        return keyStore;
    }

    private void saveKeyStore(KeyStore keyStore) throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException {
        log.info("Attempting to save keystore to path: {}", keystorePath);
        try (FileOutputStream fos = new FileOutputStream(keystorePath)) {
            keyStore.store(fos, new char[0]); // Lozinka za keystore fajl
            log.info("Keystore successfully saved.");
        }
    }

    public void saveCertificate(X509Certificate certificate, PrivateKey privateKey, String alias, String entryPassword) {
        log.info("AUDIT: Attempting to save a new private key entry to keystore with alias: {}", alias);
        try {
            KeyStore keyStore = loadKeyStore();
            X509Certificate[] certificateChain = {certificate};
            keyStore.setKeyEntry(alias, privateKey, entryPassword.toCharArray(), certificateChain);
            saveKeyStore(keyStore);
            log.info("AUDIT: Successfully saved private key entry with alias: {}", alias);
        } catch (Exception e) {
            log.error("CRITICAL: Failed to save certificate to keystore for alias: {}. Reason: {}", alias, e.getMessage(), e);
            throw new RuntimeException("Error while saving certificate to keystore", e);
        }
    }

    public void saveCertificateChain(X509Certificate[] chain, PrivateKey privateKey, String alias, String entryPassword) {
        log.info("AUDIT: Attempting to save a certificate chain to keystore with alias: {}", alias);
        try {
            KeyStore keyStore = loadKeyStore();
            keyStore.setKeyEntry(alias, privateKey, entryPassword.toCharArray(), chain);
            saveKeyStore(keyStore);
            log.info("AUDIT: Successfully saved certificate chain with alias: {}", alias);
        } catch (Exception e) {
            log.error("CRITICAL: Failed to save certificate chain to keystore for alias: {}. Reason: {}", alias, e.getMessage(), e);
            throw new RuntimeException("Error while saving certificate chain to keystore", e);
        }
    }

    public void saveTrustedCertificate(X509Certificate certificate, String alias) {
        log.info("Attempting to save a trusted certificate entry to keystore with alias: {}", alias);
        try {
            KeyStore keyStore = loadKeyStore();
            keyStore.setCertificateEntry(alias, certificate);
            saveKeyStore(keyStore);
            log.info("Successfully saved trusted certificate with alias: {}", alias);
        } catch (Exception e) {
            log.error("CRITICAL: Failed to save trusted certificate to keystore for alias: {}. Reason: {}", alias, e.getMessage(), e);
            throw new RuntimeException("Failed to save trusted certificate to keystore.", e);
        }
    }

    public X509Certificate readCertificate(String alias) {
        log.info("Attempting to read certificate from keystore with alias: {}", alias);
        try {
            KeyStore keyStore = loadKeyStore();
            if (keyStore.isKeyEntry(alias) || keyStore.isCertificateEntry(alias)) {
                X509Certificate cert = (X509Certificate) keyStore.getCertificate(alias);
                if (cert != null) {
                    log.info("Successfully read certificate with alias: {}", alias);
                } else {
                    log.warn("Certificate with alias '{}' not found, though entry exists.", alias);
                }
                return cert;
            }
            log.warn("No key entry or certificate entry found for alias: {}", alias);
        } catch (Exception e) {
            log.error("CRITICAL: Error while reading certificate from keystore with alias: {}. Reason: {}", alias, e.getMessage(), e);
            throw new RuntimeException("Error while reading certificate from keystore with alias: " + alias, e);
        }
        return null;
    }

    public PrivateKey readPrivateKey(String alias, String entryPassword) {
        log.info("AUDIT: Attempting to read a private key from keystore with alias: {}", alias);
        try {
            KeyStore keyStore = loadKeyStore();
            if (keyStore.isKeyEntry(alias)) {
                PrivateKey pKey = (PrivateKey) keyStore.getKey(alias, entryPassword.toCharArray());
                if (pKey != null) {
                    log.info("AUDIT: Successfully read private key with alias: {}", alias);
                } else {
                    // Ovo je veoma važan log - ukazuje na pogrešnu lozinku.
                    log.warn("AUDIT: Failed to read private key for alias '{}'. This may be due to an incorrect password.", alias);
                }
                return pKey;
            }
            log.warn("No key entry found for alias: {} when trying to read private key.", alias);
        } catch (Exception e) {
            log.error("CRITICAL: Error while reading private key from keystore with alias: {}. Reason: {}", alias, e.getMessage(), e);
            throw new RuntimeException("Error while reading private key from keystore with alias: " + alias, e);
        }
        return null;
    }
}