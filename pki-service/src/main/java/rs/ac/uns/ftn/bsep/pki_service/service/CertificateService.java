package rs.ac.uns.ftn.bsep.pki_service.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.pkcs.Attribute;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.style.IETFUtils;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CRLConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCSException;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequest;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import rs.ac.uns.ftn.bsep.pki_service.dto.*;
import rs.ac.uns.ftn.bsep.pki_service.model.CertificateData;
import rs.ac.uns.ftn.bsep.pki_service.model.Template;
import rs.ac.uns.ftn.bsep.pki_service.model.User;
import rs.ac.uns.ftn.bsep.pki_service.model.enums.RevocationReason;
import rs.ac.uns.ftn.bsep.pki_service.model.enums.UserRole;
import rs.ac.uns.ftn.bsep.pki_service.repository.CertificateRepository;
import rs.ac.uns.ftn.bsep.pki_service.repository.TemplateRepository;
import rs.ac.uns.ftn.bsep.pki_service.repository.UserRepository;

import java.io.IOException;
import java.io.StringReader;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.*;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
@Slf4j
public class CertificateService {

    private final CertificateRepository certificateRepository;
    private final KeystoreService keystoreService;
    private final EncryptionService encryptionService;
    private final UserRepository userRepository;
    private final TemplateRepository templateRepository;

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
                        extractFieldFromDn(cert.getSubjectDN(), "CN="),
                        extractFieldFromDn(cert.getSubjectDN(), "O="),
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

            certificateBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
            certificateBuilder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));

            ContentSigner contentSigner = new JcaContentSignerBuilder("SHA256WithRSAEncryption").setProvider("BC").build(privateKey);
            X509Certificate certificate = new JcaX509CertificateConverter().setProvider("BC").getCertificate(certificateBuilder.build(contentSigner));
            certificate.verify(publicKey);
            log.info("Root certificate for CN: {} created and verified successfully.", dto.getCommonName());

            String randomPassword = generateRandomPassword(16);
            String encryptedPassword = encryptionService.encrypt(randomPassword,userSymmetricKey);
            String alias = generateAlias(dto.getCommonName(), serialNumber);
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

            if (dto.getTemplateId() != null) {
                Template template = templateRepository.findById(dto.getTemplateId())
                        .orElseThrow(() -> new IllegalArgumentException("Template not found."));

                if (!template.getIssuer().getSerialNumber().equals(issuerData.getSerialNumber())) {
                    throw new IllegalArgumentException("Selected issuer does not match the issuer defined in the template.");
                }
                if (!dto.getCommonName().matches(template.getCommonNameRegex())) {
                    throw new IllegalArgumentException("Common Name does not match the template's validation rules.");
                }
                long requestedDurationMillis = dto.getValidTo().getTime() - dto.getValidFrom().getTime();
                long maxDurationMillis = TimeUnit.DAYS.toMillis(template.getTimeToLiveDays());
                if (requestedDurationMillis > maxDurationMillis) {
                    throw new IllegalArgumentException("Certificate duration exceeds the template's maximum Time-To-Live.");
                }
            }

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
            certificateBuilder.addExtension(Extension.cRLDistributionPoints, false, createCrlDistributionPointsExtension(issuerData.getAlias()));

            ContentSigner contentSigner = new JcaContentSignerBuilder("SHA256WithRSAEncryption").setProvider("BC").build(issuerPrivateKey);
            X509Certificate certificate = new JcaX509CertificateConverter().setProvider("BC").getCertificate(certificateBuilder.build(contentSigner));
            certificate.verify(issuerCertificate.getPublicKey());
            log.info("Intermediate certificate for CN: {} created and verified successfully.", dto.getCommonName());

            String randomPassword = generateRandomPassword(16);
            String encryptedPassword = encryptionService.encrypt(randomPassword, getUserSymmetricKey());

            String alias = generateAlias(dto.getCommonName(), serialNumber);
            X509Certificate[] chain = {certificate, issuerCertificate};
            keystoreService.saveCertificateChain(chain, privateKey, alias, randomPassword);
            log.info("Certificate chain saved to keystore under alias: {}", alias);

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

    public CertificateData createEndEntityCertificate(CreateEeCertificateDto dto, String csrPem, User finalOwner) {
        try {
            log.info("AUDIT: Starting creation of End-Entity certificate for user: {}", finalOwner.getUsername());
            User currentUser = (User) SecurityContextHolder.getContext().getAuthentication().getPrincipal();

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

            PKCS10CertificationRequest csr = parseCsr(csrPem);

            if (!isCsrSignatureValid(csr)) {
                log.warn("Failed to create EE cert. Reason: CSR signature is not valid.");
                throw new IllegalArgumentException("CSR signature is not valid.");
            }
            X500Name subject = csr.getSubject();
            PublicKey subjectPublicKey = new JcaPKCS10CertificationRequest(csr).getPublicKey();

            Template template = null;
            if (dto.getTemplateId() != null) {
                template = templateRepository.findById(dto.getTemplateId())
                        .orElseThrow(() -> new IllegalArgumentException("Template not found."));

                if (!template.getIssuer().getSerialNumber().equals(issuerData.getSerialNumber())) {
                    throw new IllegalArgumentException("Selected issuer does not match the issuer defined in the template.");
                }

                long requestedDurationMillis = dto.getValidTo().getTime() - validFrom.getTime();
                long maxDurationMillis = TimeUnit.DAYS.toMillis(template.getTimeToLiveDays());
                if (requestedDurationMillis > maxDurationMillis) {
                    throw new IllegalArgumentException("Certificate duration exceeds the template's maximum Time-To-Live.");
                }

                String commonNameFromCsr = extractCommonNameFromX500(subject);
                if (commonNameFromCsr == null || !commonNameFromCsr.matches(template.getCommonNameRegex())) {
                    throw new IllegalArgumentException("Common Name from CSR does not match the template's validation rules.");
                }

                if (template.getSubjectAlternativeNamesRegex() != null && !template.getSubjectAlternativeNamesRegex().isEmpty()) {
                    Attribute[] attributes = csr.getAttributes(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest);
                    if (attributes.length > 0) {
                        Extensions extensions = Extensions.getInstance(attributes[0].getAttrValues().getObjectAt(0));
                        GeneralNames san = GeneralNames.fromExtensions(extensions, Extension.subjectAlternativeName);
                        if (san != null) {
                            for (GeneralName name : san.getNames()) {
                                if (name.getTagNo() == GeneralName.dNSName) {
                                    String dnsName = name.getName().toString();
                                    if (!dnsName.matches(template.getSubjectAlternativeNamesRegex())) {
                                        throw new IllegalArgumentException("A Subject Alternative Name (" + dnsName + ") from CSR does not match the template's validation rules.");
                                    }
                                }
                            }
                        }
                    }
                }
            }

            PrivateKey issuerPrivateKey = keystoreService.readPrivateKey(issuerData.getAlias(), getDecryptedKeystorePassword(issuerData));
            if (issuerPrivateKey == null) throw new RuntimeException("Could not load issuer's private key.");

            BigInteger serialNumber = new BigInteger(64, new SecureRandom());
            X500Name issuerName = X500Name.getInstance(issuerCertificate.getSubjectX500Principal().getEncoded());

            JcaX509v3CertificateBuilder certificateBuilder = new JcaX509v3CertificateBuilder(
                    issuerName, serialNumber, validFrom, dto.getValidTo(), subject, subjectPublicKey);

            certificateBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
            certificateBuilder.addExtension(Extension.cRLDistributionPoints, false, createCrlDistributionPointsExtension(issuerData.getAlias()));

            if (template != null) {
                if (template.getKeyUsage() != null && !template.getKeyUsage().isEmpty()) {
                    certificateBuilder.addExtension(Extension.keyUsage, true, buildKeyUsageFromTemplate(template.getKeyUsage()));
                }
                if (template.getExtendedKeyUsage() != null && !template.getExtendedKeyUsage().isEmpty()) {
                    certificateBuilder.addExtension(Extension.extendedKeyUsage, false, buildExtendedKeyUsageFromTemplate(template.getExtendedKeyUsage()));
                }
            } else {
                certificateBuilder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment));
            }

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
            certData.setKeystorePassword(null);
            certData.setOwner(finalOwner);

            CertificateData savedCert = certificateRepository.save(certData);
            log.info("AUDIT: Successfully created End-Entity certificate with serial number: {} for owner: {}", savedCert.getSerialNumber(), finalOwner.getUsername());
            return savedCert;

        } catch (Exception e) {
            log.error("CRITICAL: Error while creating end-entity certificate. Reason: {}", e.getMessage(), e);
            throw new RuntimeException("Error while creating end-entity certificate: " + e.getMessage(), e);
        }
    }

    public void revokeCertificate(BigInteger serialNumber, RevocationReason reason) {
        log.info("AUDIT: Attempting to revoke certificate with serial number: {} for reason: {}", serialNumber, reason);
        CertificateData certToRevoke = certificateRepository.findBySerialNumber(serialNumber)
                .orElseThrow(() -> new IllegalArgumentException("Certificate with serial number " + serialNumber + " not found."));

        if (certToRevoke.isRevoked()) {
            throw new IllegalArgumentException("Certificate is already revoked.");
        }

        User currentUser = (User) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        boolean isAdmin = currentUser.getRole().equals(UserRole.ADMIN);

        if (!isAdmin && !certToRevoke.getOwner().getId().equals(currentUser.getId())) {
            log.warn("SECURITY: User {} attempted to revoke certificate {} which they do not own.", currentUser.getUsername(), serialNumber);
            throw new SecurityException("You do not have permission to revoke this certificate.");
        }

        revokeChain(certToRevoke, reason);
        log.info("AUDIT: Successfully revoked certificate with serial number: {}", serialNumber);
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
            log.info("Certificate {} is a CA. Revoking its issued certificates.", certData.getSerialNumber());
            List<CertificateData> issuedCertificates = certificateRepository.findByIssuerDN(certData.getSubjectDN());

            for (CertificateData issuedCert : issuedCertificates) {
                revokeChain(issuedCert, RevocationReason.CA_COMPROMISE);
            }
        }
    }

    public byte[] generateCrl(String issuerAlias) throws Exception {
        log.info("Generating CRL for issuer alias: {}", issuerAlias);
        CertificateData issuerData = certificateRepository.findAll().stream()
                .filter(cert -> issuerAlias.equals(cert.getAlias()))
                .findFirst()
                .orElseThrow(() -> new IllegalArgumentException("Issuer with alias '" + issuerAlias + "' not found."));

        if (!issuerData.isCa())
            throw new IllegalArgumentException("The specified alias does not belong to a CA certificate.");
        if (issuerData.isRevoked())
            throw new IllegalArgumentException("Cannot generate CRL from a revoked issuer.");

        X509Certificate issuerCert = keystoreService.readCertificate(issuerAlias);
        PrivateKey issuerPrivateKey = keystoreService.readPrivateKey(issuerAlias, getDecryptedKeystorePassword(issuerData, issuerData.getOwner()));
        if (issuerCert == null || issuerPrivateKey == null) {
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
        log.info("Found {} revoked certificates issued by {}", revokedCerts.size(), issuerAlias);

        for (CertificateData revokedCert : revokedCerts) {
            crlBuilder.addCRLEntry(
                    revokedCert.getSerialNumber(),
                    revokedCert.getRevocationDate(),
                    revokedCert.getRevocationReason().getValue()
            );
        }

        JcaContentSignerBuilder contentSignerBuilder = new JcaContentSignerBuilder("SHA256WithRSAEncryption").setProvider("BC");
        ContentSigner contentSigner = contentSignerBuilder.build(issuerPrivateKey);
        X509CRLHolder crlHolder = crlBuilder.build(contentSigner);
        return new JcaX509CRLConverter().setProvider("BC").getCRL(crlHolder).getEncoded();
    }

    private KeyUsage buildKeyUsageFromTemplate(String keyUsageString) {
        int keyUsageFlags = 0;
        String[] usages = keyUsageString.split(",");
        for (String usage : usages) {
            switch (usage.trim().toLowerCase()) {
                case "digitalsignature": keyUsageFlags |= KeyUsage.digitalSignature; break;
                case "nonrepudiation": keyUsageFlags |= KeyUsage.nonRepudiation; break;
                case "keyencipherment": keyUsageFlags |= KeyUsage.keyEncipherment; break;
                case "dataencipherment": keyUsageFlags |= KeyUsage.dataEncipherment; break;
                case "keyagreement": keyUsageFlags |= KeyUsage.keyAgreement; break;
                case "keycertsign": keyUsageFlags |= KeyUsage.keyCertSign; break;
                case "crlsign": keyUsageFlags |= KeyUsage.cRLSign; break;
                case "encipheronly": keyUsageFlags |= KeyUsage.encipherOnly; break;
                case "decipheronly": keyUsageFlags |= KeyUsage.decipherOnly; break;
            }
        }
        return new KeyUsage(keyUsageFlags);
    }

    private ExtendedKeyUsage buildExtendedKeyUsageFromTemplate(String extendedKeyUsageString) {
        List<KeyPurposeId> purposes = new ArrayList<>();
        String[] purposeValues = extendedKeyUsageString.split(",");

        for (String value : purposeValues) {
            String trimmedValue = value.trim();
            if (trimmedValue.isEmpty()) continue;

            switch (trimmedValue.toLowerCase()) {
                case "serverauth": purposes.add(KeyPurposeId.id_kp_serverAuth); break;
                case "clientauth": purposes.add(KeyPurposeId.id_kp_clientAuth); break;
                case "codesigning": purposes.add(KeyPurposeId.id_kp_codeSigning); break;
                case "emailprotection": purposes.add(KeyPurposeId.id_kp_emailProtection); break;
                case "timestamping": purposes.add(KeyPurposeId.id_kp_timeStamping); break;
                case "ocspsigning": purposes.add(KeyPurposeId.id_kp_OCSPSigning); break;
                default:
                    try {
                        purposes.add(KeyPurposeId.getInstance(new ASN1ObjectIdentifier(trimmedValue)));
                    } catch (IllegalArgumentException e) {
                        log.warn("Skipping invalid or unsupported Extended Key Usage value: '{}'", trimmedValue);
                    }
                    break;
            }
        }

        if (purposes.isEmpty()) {
            throw new IllegalArgumentException("ExtendedKeyUsage string resulted in no valid purposes.");
        }
        return new ExtendedKeyUsage(purposes.toArray(new KeyPurposeId[0]));
    }

    private String extractCommonNameFromX500(X500Name x500Name) {
        RDN cnRdn = Arrays.stream(x500Name.getRDNs(BCStyle.CN)).findFirst().orElse(null);
        return (cnRdn != null) ? IETFUtils.valueToString(cnRdn.getFirst().getValue()) : null;
    }

    private PKCS10CertificationRequest parseCsr(String csrPem) throws IOException, PKCSException {
        try (PemReader pemReader = new PemReader(new StringReader(csrPem))) {
            PemObject pemObject = pemReader.readPemObject();
            if (pemObject == null) {
                throw new IllegalArgumentException("Invalid CSR PEM string: Not a PEM-encoded content.");
            }
            return new PKCS10CertificationRequest(pemObject.getContent());
        }
    }

    private boolean isCsrSignatureValid(PKCS10CertificationRequest csr) throws OperatorCreationException, PKCSException, NoSuchAlgorithmException, InvalidKeyException, NoSuchProviderException {
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

    private CRLDistPoint createCrlDistributionPointsExtension(String issuerAlias) throws IOException {
        String crlUrl = "http://localhost:8080/api/certificates/crl/" + issuerAlias;
        GeneralName generalName = new GeneralName(GeneralName.uniformResourceIdentifier, crlUrl);
        GeneralNames generalNames = new GeneralNames(generalName);
        DistributionPointName distributionPointName = new DistributionPointName(generalNames);
        DistributionPoint distributionPoint = new DistributionPoint(distributionPointName, null, null);
        return new CRLDistPoint(new DistributionPoint[]{distributionPoint});
    }
}
