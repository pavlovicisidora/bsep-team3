package rs.ac.uns.ftn.bsep.pki_service.service;

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
public class KeystoreService {

    @Value("${keystore.path}")
    private String keystorePath;

    private KeyStore loadKeyStore() throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException {
        KeyStore keyStore = KeyStore.getInstance("JKS");
        try (FileInputStream fis = new FileInputStream(keystorePath)) {
            // Keystore fajl nema lozinku, pa je `null`
            keyStore.load(fis, null);
        } catch (IOException e) {
            // Ako fajl ne postoji, kreira se prazan keystore
            keyStore.load(null, null);
        }
        return keyStore;
    }

    private void saveKeyStore(KeyStore keyStore) throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException {
        try (FileOutputStream fos = new FileOutputStream(keystorePath)) {
            keyStore.store(fos, new char[0]);
        }
    }

    public void saveCertificate(X509Certificate certificate, PrivateKey privateKey, String alias, String entryPassword) {
        try {
            KeyStore keyStore = loadKeyStore();

            X509Certificate[] certificateChain = {certificate};
            // Koristimo prosleđenu lozinku za zaštitu privatnog ključa
            keyStore.setKeyEntry(alias, privateKey, entryPassword.toCharArray(), certificateChain);
            saveKeyStore(keyStore);

        } catch (Exception e) {
            throw new RuntimeException("Error while saving certificate to keystore", e);
        }
    }

    // Čuvanje lanca sertifikata (za Intermediate i End-Entity)
    public void saveCertificateChain(X509Certificate[] chain, PrivateKey privateKey, String alias, String entryPassword) {
        try {
            KeyStore keyStore = loadKeyStore();
            keyStore.setKeyEntry(alias, privateKey, entryPassword.toCharArray(), chain);
            saveKeyStore(keyStore);
        } catch (Exception e) {
            throw new RuntimeException("Error while saving certificate chain to keystore", e);
        }
    }

    public X509Certificate readCertificate(String alias) {
        try {
            KeyStore keyStore = loadKeyStore();
            if (keyStore.isKeyEntry(alias)) {
                return (X509Certificate) keyStore.getCertificate(alias);
            }
        } catch (Exception e) {
            throw new RuntimeException("Error while reading certificate from keystore with alias: " + alias, e);
        }
        return null;
    }

    public PrivateKey readPrivateKey(String alias, String entryPassword) {
        try {
            KeyStore keyStore = loadKeyStore();
            if (keyStore.isKeyEntry(alias)) {
                return (PrivateKey) keyStore.getKey(alias, entryPassword.toCharArray());
            }
        } catch (Exception e) {
            throw new RuntimeException("Error while reading private key from keystore with alias: " + alias, e);
        }
        return null;
    }


}
