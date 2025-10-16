package rs.ac.uns.ftn.bsep.pki_service.service;

import lombok.RequiredArgsConstructor;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import rs.ac.uns.ftn.bsep.pki_service.dto.CreateIntermediateCertificateDto;
import rs.ac.uns.ftn.bsep.pki_service.dto.CreateRootCertificateDto;
import rs.ac.uns.ftn.bsep.pki_service.model.CertificateData;
import rs.ac.uns.ftn.bsep.pki_service.model.User;
import rs.ac.uns.ftn.bsep.pki_service.repository.CertificateRepository;

import java.math.BigInteger;
import java.security.*;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.Optional;

@Service
@RequiredArgsConstructor
public class CertificateService {

    private final CertificateRepository certificateRepository;
    private final KeystoreService keystoreService;
    private final EncryptionService encryptionService;


    public CertificateData createRootCertificate(CreateRootCertificateDto dto) {
        try {

            // Dobijanje ključa ulogovanog korisnika ===
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            User currentUser = (User) authentication.getPrincipal(); // Pretpostavka da je Principal vaš User objekat
            String userSymmetricKey = currentUser.getUserSymmetricKey();

            // Veoma važna provera!
            if (userSymmetricKey == null || userSymmetricKey.isEmpty()) {
                throw new IllegalStateException("Currently logged in user does not have a symmetric key configured.");
            }

            KeyPair keyPair = generateKeyPair();
            PrivateKey privateKey = keyPair.getPrivate();
            PublicKey publicKey = keyPair.getPublic();

            X500Name subjectAndIssuer = new X500NameBuilder(BCStyle.INSTANCE)
                    .addRDN(BCStyle.CN, dto.getCommonName())
                    .addRDN(BCStyle.O, dto.getOrganization())
                    .addRDN(BCStyle.OU, dto.getOrganizationalUnit())
                    .addRDN(BCStyle.C, dto.getCountry())
                    .addRDN(BCStyle.E, dto.getEmail())
                    .build();

            BigInteger serialNumber = new BigInteger(64, new SecureRandom());

            JcaX509v3CertificateBuilder certificateBuilder = new JcaX509v3CertificateBuilder(
                    subjectAndIssuer,
                    serialNumber,
                    dto.getValidFrom(),
                    dto.getValidTo(),
                    subjectAndIssuer,
                    publicKey
            );

            certificateBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
            certificateBuilder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));

            ContentSigner contentSigner = new JcaContentSignerBuilder("SHA256WithRSAEncryption")
                    .setProvider("BC")
                    .build(privateKey);

            X509Certificate certificate = new JcaX509CertificateConverter()
                    .setProvider("BC")
                    .getCertificate(certificateBuilder.build(contentSigner));

            certificate.verify(publicKey);
            System.out.println("Certificate created and verified successfully.");


            // ---> KORAK 1: Generisanje nasumične, sigurne lozinke za ovaj sertifikat
            String randomPassword = generateRandomPassword(16);

            // ---> KORAK 2: Enkripcija te lozinke pomoću master ključa
            String encryptedPassword = encryptionService.encrypt(randomPassword,userSymmetricKey);

            // ---> KORAK 3: Čuvanje sertifikata i ključa u keystore sa ORIGINALNOM nasumičnom lozinkom
            String alias = generateAlias(dto.getCommonName(), serialNumber);
            keystoreService.saveCertificate(certificate, privateKey, alias, randomPassword);
            System.out.println("Certificate and private key saved to keystore successfully under alias: " + alias);

            // ---> KORAK 4: Priprema i čuvanje meta-podataka u bazu, uključujući ENKRIPTOVANU lozinku
            CertificateData certData = new CertificateData();
            certData.setSerialNumber(serialNumber);
            certData.setSubjectDN(certificate.getSubjectX500Principal().getName());
            certData.setIssuerDN(certificate.getIssuerX500Principal().getName());
            certData.setValidFrom(dto.getValidFrom());
            certData.setValidTo(dto.getValidTo());
            certData.setCa(true);
            certData.setAlias(alias); // Koristimo alias koji smo već jednom generisali
            certData.setKeystorePassword(encryptedPassword); // Čuvamo enkriptovanu vrednost

            return certificateRepository.save(certData);

        } catch (Exception e) {
            e.printStackTrace();
            throw new RuntimeException("Error while creating root certificate.", e);
        }
    }

    public CertificateData createIntermediateCertificate(CreateIntermediateCertificateDto dto) {
        try {
            // --- KORAK 1: Validacija i pribavljanje izdavaoca ---

            // Pronalazimo podatke o izdavaocu u bazi
            Optional<CertificateData> issuerDataOptional = certificateRepository.findBySerialNumber(new BigInteger(dto.getIssuerSerialNumber()));
            if (issuerDataOptional.isEmpty()) {
                throw new IllegalArgumentException("Issuer certificate not found.");
            }
            CertificateData issuerData = issuerDataOptional.get();

            // Provera da li je izdavalac CA sertifikat
            if (!issuerData.isCa()) {
                throw new IllegalArgumentException("Issuer is not a CA certificate.");
            }

            // Provera da li je povučen
            if (issuerData.isRevoked()) {
                throw new IllegalArgumentException("Issuer certificate has been revoked.");
            }

            // Učitavanje sertifikata izdavaoca da bismo proverili validnost
            X509Certificate issuerCertificate = keystoreService.readCertificate(issuerData.getAlias());
            if (issuerCertificate == null) {
                throw new RuntimeException("Could not load issuer certificate from keystore.");
            }

            // Provera perioda važenja izdavaoca
            issuerCertificate.checkValidity(); // Ovo baca CertificateExpiredException ili CertificateNotYetValidException

            // Provera da li je period važenja novog sertifikata unutar perioda važenja izdavaoca
            if (dto.getValidFrom().before(issuerCertificate.getNotBefore()) || dto.getValidTo().after(issuerCertificate.getNotAfter())) {
                throw new IllegalArgumentException("Validity of the new certificate must be within the validity of the issuer certificate.");
            }

            // --- KORAK 2: Učitavanje privatnog ključa izdavaoca ---
            PrivateKey issuerPrivateKey = keystoreService.readPrivateKey(
                    issuerData.getAlias(),
                    getDecryptedKeystorePassword(issuerData)
            );

            if(issuerPrivateKey == null) {
                throw new RuntimeException("Could not load issuer's private key. The password might be incorrect.");
            }
            
            // --- KORAK 3: Generisanje novog para ključeva za intermediate sertifikat ---
            KeyPair keyPair = generateKeyPair();
            PrivateKey privateKey = keyPair.getPrivate();
            PublicKey publicKey = keyPair.getPublic();


            // --- KORAK 4: Konstrukcija i potpisivanje sertifikata ---
            X500Name subject = new X500NameBuilder(BCStyle.INSTANCE)
                    .addRDN(BCStyle.CN, dto.getCommonName())
                    .addRDN(BCStyle.O, dto.getOrganization())
                    .addRDN(BCStyle.OU, dto.getOrganizationalUnit())
                    .addRDN(BCStyle.C, dto.getCountry())
                    .addRDN(BCStyle.E, dto.getEmail())
                    .build();

            BigInteger serialNumber = new BigInteger(64, new SecureRandom());

            JcaX509v3CertificateBuilder certificateBuilder = new JcaX509v3CertificateBuilder(
                    X500Name.getInstance(issuerCertificate.getSubjectX500Principal()), // Issuer
                    serialNumber,
                    dto.getValidFrom(),
                    dto.getValidTo(),
                    subject, // Subject
                    publicKey
            );

            certificateBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
            certificateBuilder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));

            ContentSigner contentSigner = new JcaContentSignerBuilder("SHA256WithRSAEncryption")
                    .setProvider("BC")
                    .build(issuerPrivateKey); // Potpisuje se privatnim ključem izdavaoca!

            X509Certificate certificate = new JcaX509CertificateConverter()
                    .setProvider("BC")
                    .getCertificate(certificateBuilder.build(contentSigner));

            // Verifikacija (opciono, ali dobra praksa)
            certificate.verify(issuerCertificate.getPublicKey());
            System.out.println("Intermediate certificate created and verified successfully.");


            // --- KORAK 5: Čuvanje novog sertifikata ---

            // Generisanje i enkripcija lozinke
            String randomPassword = generateRandomPassword(16);
            String encryptedPassword = encryptionService.encrypt(randomPassword, getUserSymmetricKey());

            // Čuvanje u keystore
            String alias = generateAlias(dto.getCommonName(), serialNumber);
            // Važno: Moramo sačuvati ceo lanac sertifikata!
            X509Certificate[] chain = {certificate, issuerCertificate};
            keystoreService.saveCertificateChain(chain, privateKey, alias, randomPassword);

            // Priprema i čuvanje meta-podataka u bazu
            CertificateData certData = new CertificateData();
            certData.setSerialNumber(serialNumber);
            certData.setSubjectDN(certificate.getSubjectX500Principal().getName());
            certData.setIssuerDN(certificate.getIssuerX500Principal().getName()); // Ovo će biti DN izdavaoca
            certData.setValidFrom(dto.getValidFrom());
            certData.setValidTo(dto.getValidTo());
            certData.setCa(true);
            certData.setAlias(alias);
            certData.setKeystorePassword(encryptedPassword);

            return certificateRepository.save(certData);

        } catch (CertificateExpiredException | CertificateNotYetValidException e) {
            throw new IllegalArgumentException("Issuer certificate is not valid at this time.", e);
        } catch (Exception e) {
            e.printStackTrace();
            throw new RuntimeException("Error while creating intermediate certificate.", e);
        }
    }

    // Pomoćna metoda za dobijanje dekriptovane lozinke
    private String getDecryptedKeystorePassword(CertificateData certData) throws Exception {
        String userSymmetricKey = getUserSymmetricKey();
        return encryptionService.decrypt(certData.getKeystorePassword(), userSymmetricKey);
    }

    // Pomoćna metoda za dobijanje ključa ulogovanog korisnika
    private String getUserSymmetricKey() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        User currentUser = (User) authentication.getPrincipal();
        String userSymmetricKey = currentUser.getUserSymmetricKey();
        if (userSymmetricKey == null || userSymmetricKey.isEmpty()) {
            throw new IllegalStateException("Currently logged in user does not have a symmetric key configured.");
        }
        return userSymmetricKey;
    }

    private String generateRandomPassword(int length) {
        String chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()";
        SecureRandom random = new SecureRandom();
        StringBuilder sb = new StringBuilder(length);
        for (int i = 0; i < length; i++) {
            sb.append(chars.charAt(random.nextInt(chars.length())));
        }
        return sb.toString();
    }

    private KeyPair generateKeyPair() throws NoSuchProviderException, NoSuchAlgorithmException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA", "BC");
        keyGen.initialize(2048, new SecureRandom());
        return keyGen.generateKeyPair();
    }

    private String generateAlias(String commonName, BigInteger serialNumber) {
        return commonName.replace(" ", "_").toLowerCase() + "_" + serialNumber.toString(16);
    }
}