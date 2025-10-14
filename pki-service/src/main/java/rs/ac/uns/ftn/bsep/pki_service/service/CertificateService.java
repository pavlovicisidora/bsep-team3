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
import org.springframework.stereotype.Service;
import rs.ac.uns.ftn.bsep.pki_service.dto.CreateRootCertificateDto;
import rs.ac.uns.ftn.bsep.pki_service.model.CertificateData;
import rs.ac.uns.ftn.bsep.pki_service.repository.CertificateRepository;

import java.math.BigInteger;
import java.security.*;
import java.security.cert.X509Certificate;

@Service
@RequiredArgsConstructor
public class CertificateService {

    private final CertificateRepository certificateRepository;

    public CertificateData createRootCertificate(CreateRootCertificateDto dto) {
        try {
            // 1. Generisanje para ključeva (privatni i javni)
            KeyPair keyPair = generateKeyPair();
            PublicKey publicKey = keyPair.getPublic();
            PrivateKey privateKey = keyPair.getPrivate();

            // 2. Priprema podataka o vlasniku (Subject) i izdavaocu (Issuer)
            // Kod root sertifikata, vlasnik i izdavalac su ista osoba
            X500Name subjectAndIssuer = new X500NameBuilder(BCStyle.INSTANCE)
                    .addRDN(BCStyle.CN, dto.getCommonName())
                    .addRDN(BCStyle.O, dto.getOrganization())
                    .addRDN(BCStyle.OU, dto.getOrganizationalUnit())
                    .addRDN(BCStyle.C, dto.getCountry())
                    .addRDN(BCStyle.E, dto.getEmail())
                    .build();

            // 3. Generisanje serijskog broja
            // Mora biti jedinstven za svakog izdavaoca
            BigInteger serialNumber = new BigInteger(64, new SecureRandom());

            // 4. Postavljanje perioda validnosti
            // DTO već sadrži validFrom i validTo

            // 5. Kreiranje "graditelja" sertifikata
            JcaX509v3CertificateBuilder certificateBuilder = new JcaX509v3CertificateBuilder(
                    subjectAndIssuer, // Issuer
                    serialNumber,
                    dto.getValidFrom(),
                    dto.getValidTo(),
                    subjectAndIssuer, // Subject
                    publicKey // Javni ključ subjekta
            );

            // 6. Dodavanje ekstenzija (ključno za CA sertifikat)
            // BasicConstraints: Označava da je sertifikat CA (cA:true) i da može da potpisuje druge sertifikate.
            certificateBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
            // KeyUsage: Definiše svrhu ključa. Za CA, to je potpisivanje sertifikata (keyCertSign) i CRL listi (cRLSign).
            certificateBuilder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));

            // 7. Potpisivanje sertifikata
            // Sertifikat se potpisuje privatnim ključem izdavaoca (u ovom slučaju, samim sobom)
            ContentSigner contentSigner = new JcaContentSignerBuilder("SHA256WithRSAEncryption")
                    .setProvider("BC")
                    .build(privateKey);

            // 8. Generisanje finalnog X509 sertifikata
            X509Certificate certificate = new JcaX509CertificateConverter()
                    .setProvider("BC")
                    .getCertificate(certificateBuilder.build(contentSigner));

            // Provera validnosti (opciono, ali dobra praksa)
            certificate.verify(publicKey);
            System.out.println("Certificate created and verified successfully.");

            // TODO: ČUVANJE U KEYSTORE
            // Ovde dolazi logika za čuvanje sertifikata i privatnog ključa u keystore fajl.
            // Za sada, samo ćemo sačuvati meta-podatke u bazu.

            // 9. Čuvanje meta-podataka u bazu
            CertificateData certData = new CertificateData();
            certData.setSerialNumber(serialNumber);
            certData.setSubjectDN(certificate.getSubjectX500Principal().getName());
            certData.setIssuerDN(certificate.getIssuerX500Principal().getName());
            certData.setValidFrom(dto.getValidFrom());
            certData.setValidTo(dto.getValidTo());
            certData.setCa(true);
            certData.setAlias(generateAlias(dto.getCommonName(), serialNumber)); // Kreiraćemo helper metodu za ovo

            return certificateRepository.save(certData);

        } catch (Exception e) {
            // Obavezno dodati bolji exception handling
            e.printStackTrace();
            throw new RuntimeException("Error while creating root certificate.", e);
        }
    }

    private KeyPair generateKeyPair() throws NoSuchProviderException, NoSuchAlgorithmException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA", "BC");
        keyGen.initialize(2048, new SecureRandom());
        return keyGen.generateKeyPair();
    }

    private String generateAlias(String commonName, BigInteger serialNumber) {
        // Jednostavan način da se generiše jedinstveni alias
        return commonName.replace(" ", "_").toLowerCase() + "_" + serialNumber.toString(16);
    }
}
