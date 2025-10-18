package rs.ac.uns.ftn.bsep.pki_service.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j; // <-- DODATO
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CRLConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequest;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;
import rs.ac.uns.ftn.bsep.pki_service.dto.*;
import rs.ac.uns.ftn.bsep.pki_service.model.CertificateData;
import rs.ac.uns.ftn.bsep.pki_service.model.User;
import rs.ac.uns.ftn.bsep.pki_service.model.enums.RevocationReason;
import rs.ac.uns.ftn.bsep.pki_service.model.enums.UserRole;
import rs.ac.uns.ftn.bsep.pki_service.repository.CertificateRepository;
import rs.ac.uns.ftn.bsep.pki_service.repository.UserRepository;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.CRLDistPoint;

import java.io.InputStreamReader;
import java.io.StringReader;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.*;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
@Slf4j // <-- DODATO
public class CertificateService {

    private final CertificateRepository certificateRepository;
    private final KeystoreService keystoreService;
    private final EncryptionService encryptionService;
    private final UserRepository userRepository;

    public List<IssuerDto> getAvailableIssuers() {
        User currentUser = (User) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        log.info("Fetching available issuers for user: {}", currentUser.getUsername());
        List<CertificateData> potentialIssuers;

        assert currentUser != null;
        if (currentUser.getRole().equals(UserRole.ORDINARY_USER)) {
            Date now = new Date();
            potentialIssuers = certificateRepository.findByIsCaTrueAndIsRevokedFalseAndValidFromBeforeAndValidToAfter(now, now);
        }
        else  if (currentUser.getRole().equals(UserRole.ADMIN)) {
            potentialIssuers = certificateRepository.findByIsCaTrueAndIsRevokedFalse();
        } else  {
            potentialIssuers = certificateRepository.findByIsCaTrueAndIsRevokedFalseAndOwner(currentUser);
        }

        return potentialIssuers.stream()
                .map(cert -> new IssuerDto(
                        cert.getSerialNumber().toString(),
                        extractFieldFromDn(cert.getSubjectDN(), "CN"),
                        extractFieldFromDn(cert.getSubjectDN(), "O"),
                        cert.getValidTo()))
                .collect(Collectors.toList());
    }

    private String extractFieldFromDn(String dn, String field) {
        String prefix = field + "=";
        for (String part : dn.split(",")) {
            part = part.trim();
            if (part.startsWith(prefix)) {
                return part.substring(prefix.length());
            }
        }
        return "N/A";
    }

    public List<CertificateDetailsDto> getAllCertificatesForCurrentUser() {
        User currentUser = (User) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        log.info("Fetching all certificates for user: {}", currentUser.getUsername());
        List<CertificateData> certificates;

        switch (currentUser.getRole()) {
            case ADMIN:
                certificates = certificateRepository.findAll();
                break;
            case CA_USER:
                certificates = certificateRepository.findByOwner(currentUser);
                break;
            case ORDINARY_USER:
                certificates = certificateRepository.findByOwnerAndIsCaFalse(currentUser);
                break;
            default:
                certificates = List.of();
                break;
        }

        return certificates.stream().map(cert -> new CertificateDetailsDto(
                cert.getSerialNumber().toString(),
                extractFieldFromDn(cert.getSubjectDN(), "CN"),
                extractFieldFromDn(cert.getIssuerDN(), "CN"),
                cert.getValidFrom(),
                cert.getValidTo(),
                cert.isCa(),
                cert.isRevoked(),
                cert.getRevocationReason(),
                cert.getOwner().getUsername(),
                cert.getAlias()
        )).collect(Collectors.toList());
    }

    public CertificateData createRootCertificate(CreateRootCertificateDto dto) {
        try {
            log.info("AUDIT: Starting creation of Root certificate for CN: {}", dto.getCommonName());
            User currentUser = (User) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
            String userSymmetricKey = currentUser.getUserSymmetricKey();

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
                    subjectAndIssuer, serialNumber, dto.getValidFrom(), dto.getValidTo(), subjectAndIssuer, publicKey);
            String alias = generateAlias(dto.getCommonName(), serialNumber);
            certificateBuilder.addExtension(Extension.cRLDistributionPoints, false, createCrlDistributionPointsExtension(alias));

            certificateBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
            certificateBuilder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));

            ContentSigner contentSigner = new JcaContentSignerBuilder("SHA256WithRSAEncryption").setProvider("BC").build(privateKey);
            X509Certificate certificate = new JcaX509CertificateConverter().setProvider("BC").getCertificate(certificateBuilder.build(contentSigner));
            certificate.verify(publicKey);
            log.info("Root certificate for CN: {} created and verified successfully.", dto.getCommonName());

            String randomPassword = generateRandomPassword(16);
            String encryptedPassword = encryptionService.encrypt(randomPassword,userSymmetricKey);
            keystoreService.saveCertificate(certificate, privateKey, alias, randomPassword);
            log.info("Certificate and private key saved to keystore under alias: {}", alias);

            User owner = currentUser;
            if (currentUser.getRole().equals(UserRole.ADMIN) && dto.getOwnerId() != null) {
                owner = userRepository.findById(dto.getOwnerId())
                        .orElseThrow(() -> new IllegalArgumentException("User with specified ownerId not found."));
            }

            CertificateData certData = new CertificateData();
            certData.setSerialNumber(serialNumber);
            certData.setSubjectDN(certificate.getSubjectX500Principal().getName());
            certData.setIssuerDN(certificate.getIssuerX500Principal().getName());
            certData.setValidFrom(dto.getValidFrom());
            certData.setValidTo(dto.getValidTo());
            certData.setCa(true);
            certData.setAlias(alias);
            certData.setKeystorePassword(encryptedPassword);
            certData.setOwner(owner);

            CertificateData savedCert = certificateRepository.save(certData);
            log.info("AUDIT: Successfully created Root certificate with serial number: {} and alias: {}", savedCert.getSerialNumber(), savedCert.getAlias());
            return savedCert;

        } catch (Exception e) {
            log.error("CRITICAL: Error while creating root certificate. Reason: {}", e.getMessage(), e);
            throw new RuntimeException("Error while creating root certificate.", e);
        }
    }

    public CertificateData createIntermediateCertificate(CreateIntermediateCertificateDto dto) {
        try {
            log.info("AUDIT: Starting creation of Intermediate certificate for CN: {}", dto.getCommonName());
            User currentUser = (User) SecurityContextHolder.getContext().getAuthentication().getPrincipal();

            Optional<CertificateData> issuerDataOptional = certificateRepository.findBySerialNumber(new BigInteger(dto.getIssuerSerialNumber()));
            if (issuerDataOptional.isEmpty()) {
                log.warn("Failed to create intermediate cert. Reason: Issuer not found with serial number: {}", dto.getIssuerSerialNumber());
                throw new IllegalArgumentException("Issuer certificate not found.");
            }
            CertificateData issuerData = issuerDataOptional.get();

            assert currentUser != null;
            if (UserRole.CA_USER.equals(currentUser.getRole()) && !issuerData.getOwner().getId().equals(currentUser.getId())) {
                log.warn("SECURITY: User {} tried to issue certificate with issuer {} which they do not own.", currentUser.getUsername(), issuerData.getSerialNumber());
                throw new SecurityException("CA user can only use certificates they own.");
            }
            if (!issuerData.isCa()) {
                log.warn("Failed to create intermediate cert. Reason: Issuer {} is not a CA.", issuerData.getSerialNumber());
                throw new IllegalArgumentException("Issuer is not a CA certificate.");
            }
            if (issuerData.isRevoked()) {
                log.warn("Failed to create intermediate cert. Reason: Issuer {} has been revoked.", issuerData.getSerialNumber());
                throw new IllegalArgumentException("Issuer certificate has been revoked.");
            }

            X509Certificate issuerCertificate = keystoreService.readCertificate(issuerData.getAlias());
            if (issuerCertificate == null) {
                log.error("CRITICAL: Could not load issuer certificate {} from keystore.", issuerData.getAlias());
                throw new RuntimeException("Could not load issuer certificate from keystore.");
            }

            issuerCertificate.checkValidity();

            if (dto.getValidFrom().before(issuerCertificate.getNotBefore()) || dto.getValidTo().after(issuerCertificate.getNotAfter())) {
                log.warn("Failed to create intermediate cert. Reason: Validity period is outside issuer's validity.");
                throw new IllegalArgumentException("Validity of the new certificate must be within the validity of the issuer certificate.");
            }

            PrivateKey issuerPrivateKey = keystoreService.readPrivateKey(issuerData.getAlias(), getDecryptedKeystorePassword(issuerData));
            if(issuerPrivateKey == null) {
                log.error("CRITICAL: Could not load issuer's private key for alias {}. The password might be incorrect.", issuerData.getAlias());
                throw new RuntimeException("Could not load issuer's private key. The password might be incorrect.");
            }

            KeyPair keyPair = generateKeyPair();
            PrivateKey privateKey = keyPair.getPrivate();
            PublicKey publicKey = keyPair.getPublic();

            X500Name subject = new X500NameBuilder(BCStyle.INSTANCE)
                    .addRDN(BCStyle.CN, dto.getCommonName()).addRDN(BCStyle.O, dto.getOrganization())
                    .addRDN(BCStyle.OU, dto.getOrganizationalUnit()).addRDN(BCStyle.C, dto.getCountry())
                    .addRDN(BCStyle.E, dto.getEmail()).build();

            BigInteger serialNumber = new BigInteger(64, new SecureRandom());
            X500Name issuerName = X500Name.getInstance(issuerCertificate.getSubjectX500Principal().getEncoded());

            JcaX509v3CertificateBuilder certificateBuilder = new JcaX509v3CertificateBuilder(
                    issuerName, serialNumber, dto.getValidFrom(), dto.getValidTo(), subject, publicKey);

            certificateBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
            certificateBuilder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));

            ContentSigner contentSigner = new JcaContentSignerBuilder("SHA256WithRSAEncryption").setProvider("BC").build(issuerPrivateKey);
            X509Certificate certificate = new JcaX509CertificateConverter().setProvider("BC").getCertificate(certificateBuilder.build(contentSigner));
            certificate.verify(issuerCertificate.getPublicKey());
            log.info("Intermediate certificate for CN: {} created and verified successfully.", dto.getCommonName());

            String alias = generateAlias(dto.getCommonName(), serialNumber);
            X509Certificate[] chain = {certificate, issuerCertificate};
            log.info("Certificate chain saved to keystore under alias: {}", alias);

            User owner = currentUser;
            if (currentUser.getRole().equals(UserRole.ADMIN) && dto.getOwnerId() != null) {
                owner = userRepository.findById(dto.getOwnerId())
                        .orElseThrow(() -> new IllegalArgumentException("User with specified ownerId not found."));
            }

            String randomPassword = generateRandomPassword(16);
            String encryptedPassword = encryptionService.encrypt(randomPassword, getUserSymmetricKey(owner));

            keystoreService.saveCertificateChain(chain, privateKey, alias, randomPassword);
            CertificateData certData = new CertificateData();
            certData.setSerialNumber(serialNumber);
            certData.setSubjectDN(certificate.getSubjectX500Principal().getName());
            certData.setIssuerDN(certificate.getIssuerX500Principal().getName());
            certData.setValidFrom(dto.getValidFrom());
            certData.setValidTo(dto.getValidTo());
            certData.setCa(true);
            certData.setAlias(alias);
            certData.setKeystorePassword(encryptedPassword);
            certData.setOwner(owner);

            CertificateData savedCert = certificateRepository.save(certData);
            log.info("AUDIT: Successfully created Intermediate certificate with serial number: {} and alias: {}", savedCert.getSerialNumber(), savedCert.getAlias());
            return savedCert;

        } catch (CertificateExpiredException | CertificateNotYetValidException e) {
            log.warn("Failed to create intermediate cert. Reason: Issuer certificate is not valid at this time.");
            throw new IllegalArgumentException("Issuer certificate is not valid at this time.", e);
        } catch (Exception e) {
            log.error("CRITICAL: Error while creating intermediate certificate. Reason: {}", e.getMessage(), e);
            throw new RuntimeException("Error while creating intermediate certificate.", e);
        }
    }

    public CertificateData createEndEntityCertificate(CreateEeCertificateDto dto, String csrPem,  User finalOwner) {
        try {
            log.info("AUDIT: Starting creation of End-Entity certificate for user: {}", finalOwner.getUsername());
            User currentUser = (User) Objects.requireNonNull(SecurityContextHolder.getContext().getAuthentication()).getPrincipal();

            Optional<CertificateData> issuerDataOptional = certificateRepository.findBySerialNumber(new BigInteger(dto.getIssuerSerialNumber()));
            if (issuerDataOptional.isEmpty()) {
                log.warn("Failed to create EE cert. Reason: Issuer not found with serial number: {}", dto.getIssuerSerialNumber());
                throw new IllegalArgumentException("Issuer certificate not found.");
            }
            CertificateData issuerData = issuerDataOptional.get();

            if (UserRole.CA_USER.equals(currentUser.getRole()) && !issuerData.getOwner().getId().equals(currentUser.getId())) {
                log.warn("SECURITY: User {} tried to issue EE certificate with issuer {} which they do not own.", currentUser.getUsername(), issuerData.getSerialNumber());
                throw new SecurityException("CA user can only use certificates they own.");
            }
            if (!issuerData.isCa()) throw new IllegalArgumentException("Issuer is not a CA certificate.");
            if (issuerData.isRevoked()) throw new IllegalArgumentException("Issuer certificate has been revoked.");

            X509Certificate issuerCertificate = keystoreService.readCertificate(issuerData.getAlias());
            if (issuerCertificate == null) throw new RuntimeException("Could not load issuer certificate from keystore.");

            issuerCertificate.checkValidity();

            Date validFrom = new Date();
            if (validFrom.before(issuerCertificate.getNotBefore()) || dto.getValidTo().after(issuerCertificate.getNotAfter())) {
                throw new IllegalArgumentException("Validity of the new certificate must be within the validity of the issuer certificate.");
            }

            PrivateKey issuerPrivateKey = keystoreService.readPrivateKey(issuerData.getAlias(), getDecryptedKeystorePassword(issuerData));
            if (issuerPrivateKey == null) throw new RuntimeException("Could not load issuer's private key.");

            PKCS10CertificationRequest csr = parseCsr(csrPem);

            if (!isCsrSignatureValid(csr)) {
                log.warn("Failed to create EE cert. Reason: CSR signature is not valid.");
                throw new IllegalArgumentException("CSR signature is not valid.");
            }

            X500Name subject = csr.getSubject();
            PublicKey subjectPublicKey = new JcaPKCS10CertificationRequest(csr).getPublicKey();

            BigInteger serialNumber = new BigInteger(64, new SecureRandom());
            X500Name issuerName = X500Name.getInstance(issuerCertificate.getSubjectX500Principal().getEncoded());

            JcaX509v3CertificateBuilder certificateBuilder = new JcaX509v3CertificateBuilder(
                    issuerName, serialNumber, validFrom, dto.getValidTo(), subject, subjectPublicKey);

            certificateBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
            certificateBuilder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment));

            ContentSigner contentSigner = new JcaContentSignerBuilder("SHA256WithRSAEncryption").setProvider("BC").build(issuerPrivateKey);
            X509Certificate certificate = new JcaX509CertificateConverter().setProvider("BC").getCertificate(certificateBuilder.build(contentSigner));
            certificate.verify(issuerCertificate.getPublicKey());
            log.info("End-Entity certificate for subject '{}' created and verified successfully.", subject.toString());

            String commonNameFromCsr = extractFieldFromDn(subject.toString(), "CN");
            String alias = generateAlias(commonNameFromCsr, serialNumber);

            keystoreService.saveTrustedCertificate(certificate, alias);
            log.info("Trusted EE certificate saved to keystore under alias: {}", alias);

            CertificateData certData = new CertificateData();
            certData.setSerialNumber(serialNumber);
            certData.setSubjectDN(certificate.getSubjectX500Principal().getName());
            certData.setIssuerDN(certificate.getIssuerX500Principal().getName());
            certData.setValidFrom(validFrom);
            certData.setValidTo(dto.getValidTo());
            certData.setCa(false);
            certData.setAlias(alias);
            certData.setKeystorePassword("");
            certData.setOwner(finalOwner);

            CertificateData savedCert = certificateRepository.save(certData);
            log.info("AUDIT: Successfully created End-Entity certificate with serial number: {} for owner: {}", savedCert.getSerialNumber(), finalOwner.getUsername());
            return savedCert;

        } catch (Exception e) {
            log.error("CRITICAL: Error while creating end-entity certificate. Reason: {}", e.getMessage(), e);
            throw new RuntimeException("Error while creating end-entity certificate.", e);
        }
    }

    public void revokeCertificate(BigInteger serialNumber, RevocationReason reason) {
        User currentUser = (User) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        log.info("AUDIT: User '{}' is attempting to revoke certificate with serial number: {}. Reason: {}",
                currentUser.getUsername(), serialNumber, reason);

        CertificateData certToRevoke = certificateRepository.findBySerialNumber(serialNumber)
                .orElseThrow(() -> {
                    log.warn("Revocation failed. Certificate with serial number {} not found.", serialNumber);
                    return new IllegalArgumentException("Certificate with serial number " + serialNumber + " not found.");
                });

        if (certToRevoke.isRevoked()) {
            log.warn("Revocation failed. Certificate {} is already revoked.", serialNumber);
            throw new IllegalArgumentException("Certificate is already revoked.");
        }

        boolean isAdmin = currentUser.getRole().equals(UserRole.ADMIN);

        if (!isAdmin && !certToRevoke.getOwner().getId().equals(currentUser.getId())) {
            log.warn("SECURITY: User '{}' does not have permission to revoke certificate {}.", currentUser.getUsername(), serialNumber);
            throw new SecurityException("You do not have permission to revoke this certificate.");
        }

        log.info("Permission granted. Proceeding to revoke certificate {} and its chain.", serialNumber);
        revokeChain(certToRevoke, reason);
    }

    public byte[] generateCrl(String issuerAlias) throws Exception {
        log.info("CRL_GENERATION: Starting process for issuer alias: {}", issuerAlias);

        CertificateData issuerData = certificateRepository.findAll().stream()
                .filter(cert -> issuerAlias.equals(cert.getAlias()))
                .findFirst()
                .orElseThrow(() -> {
                    log.warn("CRL generation failed. Issuer with alias '{}' not found in database.", issuerAlias);
                    return new IllegalArgumentException("Issuer with alias '" + issuerAlias + "' not found.");
                });
        log.info("-> Found issuer in DB. Alias: {}, isCa: {}, isRevoked: {}", issuerData.getAlias(), issuerData.isCa(), issuerData.isRevoked());
        if (!issuerData.isCa()) {
            log.warn("CRL generation failed for alias '{}'. Reason: Certificate is not a CA.", issuerAlias);
            throw new IllegalArgumentException("The specified alias does not belong to a CA certificate.");
        }

        if (issuerData.isRevoked()) {
            log.warn("CRL generation failed for alias '{}'. Reason: Issuer certificate is revoked.", issuerAlias);
            throw new IllegalArgumentException("Cannot generate CRL from a revoked issuer.");
        }

        X509Certificate issuerCert = keystoreService.readCertificate(issuerAlias);
        PrivateKey issuerPrivateKey = keystoreService.readPrivateKey(
                issuerAlias,
                getDecryptedKeystorePassword(issuerData, issuerData.getOwner())
        );

        if (issuerCert == null || issuerPrivateKey == null) {
            log.error("CRITICAL: Could not load issuer's certificate or private key from keystore for alias '{}'.", issuerAlias);
            throw new RuntimeException("Could not load issuer's certificate or private key from keystore.");
        }

        Date now = new Date();
        Calendar calendar = Calendar.getInstance();
        calendar.setTime(now);
        calendar.add(Calendar.DAY_OF_YEAR, 7);
        Date nextUpdate = calendar.getTime();

        X500Name issuerX500Name = X500Name.getInstance(issuerCert.getSubjectX500Principal().getEncoded());
        X509v2CRLBuilder crlBuilder = new X509v2CRLBuilder(issuerX500Name, now);
        crlBuilder.setNextUpdate(nextUpdate);

        List<CertificateData> revokedCerts = certificateRepository.findByIssuerDNAndIsRevokedTrue(issuerData.getSubjectDN());
        log.info("Found {} revoked certificates issued by '{}' to add to the CRL.", revokedCerts.size(), issuerAlias);

        for (CertificateData revokedCert : revokedCerts) {
            crlBuilder.addCRLEntry(
                    revokedCert.getSerialNumber(),
                    revokedCert.getRevocationDate(),
                    revokedCert.getRevocationReason().getValue()
            );
        }

        JcaContentSignerBuilder contentSignerBuilder = new JcaContentSignerBuilder("SHA256WithRSAEncryption")
                .setProvider("BC");
        ContentSigner contentSigner = contentSignerBuilder.build(issuerPrivateKey);

        X509CRLHolder crlHolder = crlBuilder.build(contentSigner);

        X509CRL crl = new JcaX509CRLConverter().setProvider("BC").getCRL(crlHolder);
        
        log.info("CRL_GENERATION: Successfully generated CRL for issuer alias: {}", issuerAlias);
        return crl.getEncoded();
    }

    private void revokeChain(CertificateData certData, RevocationReason reason) {
        if (certData.isRevoked()) {
            return;
        }

        certData.setRevoked(true);
        certData.setRevocationReason(reason);
        certData.setRevocationDate(new Date());
        certificateRepository.save(certData);

        log.info("Revoked certificate with SN: {}", certData.getSerialNumber());

        if (certData.isCa()) {
            List<CertificateData> issuedCertificates = certificateRepository.findByIssuerDN(certData.getSubjectDN());

            for (CertificateData issuedCert : issuedCertificates) {
                revokeChain(issuedCert, RevocationReason.CA_COMPROMISE);
            }
        }
    }

    private PKCS10CertificationRequest parseCsr(String csrPem) throws Exception {
        try (PemReader pemReader = new PemReader(new StringReader(csrPem))) {
            PemObject pemObject = pemReader.readPemObject();
            if (pemObject == null) {
                throw new IllegalArgumentException("Invalid CSR PEM string.");
            }
            return new PKCS10CertificationRequest(pemObject.getContent());
        }
    }

    private boolean isCsrSignatureValid(PKCS10CertificationRequest csr) throws Exception {
        JcaPKCS10CertificationRequest jcaCsr = new JcaPKCS10CertificationRequest(csr);
        ContentVerifierProvider verifierProvider = new JcaContentVerifierProviderBuilder().setProvider("BC").build(jcaCsr.getPublicKey());
        return csr.isSignatureValid(verifierProvider);
    }

    private String getDecryptedKeystorePassword(CertificateData certData) throws Exception {
        String userSymmetricKey = getUserSymmetricKey();
        return encryptionService.decrypt(certData.getKeystorePassword(), userSymmetricKey);
    }

    private String getDecryptedKeystorePassword(CertificateData certData, User owner) throws Exception {
        String userSymmetricKey = owner.getUserSymmetricKey();
        if (userSymmetricKey == null || userSymmetricKey.isEmpty()) {
            throw new IllegalStateException("Certificate owner (ID: " + owner.getId() + ") does not have a symmetric key configured.");
        }
        return encryptionService.decrypt(certData.getKeystorePassword(), userSymmetricKey);
    }

    private String getUserSymmetricKey() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        User currentUser = (User) authentication.getPrincipal();
        String userSymmetricKey = currentUser.getUserSymmetricKey();
        if (userSymmetricKey == null || userSymmetricKey.isEmpty()) {
            throw new IllegalStateException("Currently logged in user does not have a symmetric key configured.");
        }
        return userSymmetricKey;
    }

    private String getUserSymmetricKey(User owner) {
        String userSymmetricKey = owner.getUserSymmetricKey();
        if (userSymmetricKey == null || userSymmetricKey.isEmpty()) {
            throw new IllegalStateException("Owner does not have a symmetric key configured.");
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

    private CRLDistPoint createCrlDistributionPointsExtension(String issuerAlias) {
        String crlUrl = "http://localhost:8080/api/certificates/crl/" + issuerAlias;

        GeneralName generalName = new GeneralName(GeneralName.uniformResourceIdentifier, crlUrl);
        GeneralNames generalNames = new GeneralNames(generalName);
        DistributionPointName distributionPointName = new DistributionPointName(generalNames);
        DistributionPoint distributionPoint = new DistributionPoint(distributionPointName, null, null);

        return new CRLDistPoint(new DistributionPoint[]{distributionPoint});
    }
}