package rs.ac.uns.ftn.bsep.pki_service.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.pkcs.Attribute;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.style.IETFUtils;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import rs.ac.uns.ftn.bsep.pki_service.dto.CreateIntermediateCertificateDto;
import rs.ac.uns.ftn.bsep.pki_service.dto.TemplateCreateDto;
import rs.ac.uns.ftn.bsep.pki_service.dto.TemplateResponseDto;
import rs.ac.uns.ftn.bsep.pki_service.model.CertificateData;
import rs.ac.uns.ftn.bsep.pki_service.model.Template;
import rs.ac.uns.ftn.bsep.pki_service.model.User;
import rs.ac.uns.ftn.bsep.pki_service.model.enums.UserRole;
import rs.ac.uns.ftn.bsep.pki_service.repository.CertificateRepository;
import rs.ac.uns.ftn.bsep.pki_service.repository.TemplateRepository;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
@Slf4j
public class TemplateService {

    private final TemplateRepository templateRepository;
    private final CertificateRepository certificateRepository;

    public Template createTemplate(TemplateCreateDto dto) {
        User currentUser = (User) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        log.info("AUDIT: User '{}' is attempting to create a new template named '{}' for issuer SN '{}'.",
                currentUser.getUsername(), dto.getName(), dto.getIssuerSerialNumber());

        if (!currentUser.getRole().equals(UserRole.CA_USER)) {
            log.warn("SECURITY: User '{}' with role '{}' is not authorized to create templates.",
                    currentUser.getUsername(), currentUser.getRole());
            throw new SecurityException("Only CA users can create templates.");
        }

        CertificateData issuer = certificateRepository
                .findBySerialNumber(new BigInteger(dto.getIssuerSerialNumber()))
                .orElseThrow(() -> {
                    log.warn("Template creation failed. Issuer with SN '{}' not found.", dto.getIssuerSerialNumber());
                    return new IllegalArgumentException("Issuer not found.");
                });

        if (!issuer.getOwner().getId().equals(currentUser.getId())) {
            log.warn("SECURITY: User '{}' attempted to create a template for issuer SN '{}' which they do not own.",
                    currentUser.getUsername(), dto.getIssuerSerialNumber());
            throw new SecurityException("You can only create templates for CAs you own.");
        }

        if (!issuer.isCa()) {
            log.warn("Template creation failed. Issuer with SN '{}' is not a CA certificate.", dto.getIssuerSerialNumber());
            throw new IllegalArgumentException("The selected issuer must be a CA certificate.");
        }

        Template template = new Template();
        template.setName(dto.getName());
        template.setOwner(currentUser);
        template.setIssuer(issuer);
        template.setCommonNameRegex(dto.getCommonNameRegex());
        template.setSubjectAlternativeNamesRegex(dto.getSubjectAlternativeNamesRegex());
        template.setTimeToLiveDays(dto.getTimeToLiveDays());

        if (dto.getKeyUsage() != null && !dto.getKeyUsage().isEmpty()) {
            template.setKeyUsage(String.join(",", dto.getKeyUsage()));
        }

        if (dto.getExtendedKeyUsage() != null && !dto.getExtendedKeyUsage().isEmpty()) {
            template.setExtendedKeyUsage(String.join(",", dto.getExtendedKeyUsage()));
        }

        Template savedTemplate = templateRepository.save(template);
        log.info("AUDIT: Successfully created template with ID: {} and name: '{}'.", savedTemplate.getId(), savedTemplate.getName());
        return savedTemplate;
    }

    public List<TemplateResponseDto> getTemplatesForCurrentUser() {
        User currentUser = (User) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        assert currentUser != null;
        log.info("Fetching templates for user '{}'.", currentUser.getUsername());
        if (!currentUser.getRole().equals(UserRole.CA_USER)) {
            return List.of();
        }
        List<Template> templates = templateRepository.findByOwner(currentUser);

        return templates.stream()
                .map(TemplateResponseDto::new)
                .collect(Collectors.toList());
    }

    public void deleteTemplate(Long id) {
        User currentUser = (User) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        log.info("AUDIT: User '{}' is attempting to delete template with ID: {}.", currentUser.getUsername(), id);

        Template template = templateRepository.findById(id)
                .orElseThrow(() -> {
                    log.warn("Template deletion failed. Template with ID '{}' not found.", id);
                    return new IllegalArgumentException("Template not found.");
                });

        if (!template.getOwner().getId().equals(currentUser.getId())) {
            log.warn("SECURITY: User '{}' attempted to delete template ID '{}' which they do not own.",
                    currentUser.getUsername(), id);
            throw new SecurityException("You do not have permission to delete this template.");
        }

        templateRepository.delete(template);
        log.info("AUDIT: Successfully deleted template with ID: {}.", id);
    }

    public void validateIntermediateCertDtoWithTemplate(Template template, CreateIntermediateCertificateDto dto, CertificateData issuerData) {
        log.debug("Validating Intermediate DTO against template ID: {}", template.getId());
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

    public void validateCsrWithTemplate(Template template, PKCS10CertificationRequest csr, Date validTo, CertificateData issuerData) {
        log.debug("Validating CSR against template ID: {}", template.getId());
        Date validFrom = new Date();
        X500Name subject = csr.getSubject();

        if (!template.getIssuer().getSerialNumber().equals(issuerData.getSerialNumber())) {
            throw new IllegalArgumentException("Selected issuer does not match the issuer defined in the template.");
        }
        long requestedDurationMillis = validTo.getTime() - validFrom.getTime();
        long maxDurationMillis = TimeUnit.DAYS.toMillis(template.getTimeToLiveDays());
        if (requestedDurationMillis > maxDurationMillis) {
            throw new IllegalArgumentException("Certificate duration exceeds the template's maximum Time-To-Live.");
        }
        String commonNameFromCsr = extractCommonNameFromX500(subject);
        if (commonNameFromCsr == null || !commonNameFromCsr.matches(template.getCommonNameRegex())) {
            throw new IllegalArgumentException("Common Name from CSR does not match the template's validation rules.");
        }
        if (template.getSubjectAlternativeNamesRegex() != null && !template.getSubjectAlternativeNamesRegex().isEmpty()) {
            validateSanInCsr(csr, template.getSubjectAlternativeNamesRegex());
        }
    }

    public void applyTemplateExtensions(JcaX509v3CertificateBuilder certificateBuilder, Template template) {
        log.debug("Applying extensions from template ID: {}", template.getId());
        try {
            if (template.getKeyUsage() != null && !template.getKeyUsage().isEmpty()) {
                certificateBuilder.addExtension(Extension.keyUsage, true, buildKeyUsage(template.getKeyUsage()));
            }
            if (template.getExtendedKeyUsage() != null && !template.getExtendedKeyUsage().isEmpty()) {
                certificateBuilder.addExtension(Extension.extendedKeyUsage, false, buildExtendedKeyUsage(template.getExtendedKeyUsage()));
            }
        } catch (Exception e) {
            log.error("CRITICAL: Error applying template extensions for template ID: {}. Reason: {}", template.getId(), e.getMessage(), e);
            throw new RuntimeException("Failed to apply template extensions.", e);
        }
    }


    private void validateSanInCsr(PKCS10CertificationRequest csr, String sanRegex) {
        Attribute[] attributes = csr.getAttributes(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest);
        if (attributes.length > 0) {
            Extensions extensions = Extensions.getInstance(attributes[0].getAttrValues().getObjectAt(0));
            GeneralNames san = GeneralNames.fromExtensions(extensions, Extension.subjectAlternativeName);
            if (san != null) {
                for (GeneralName name : san.getNames()) {
                    if (name.getTagNo() == GeneralName.dNSName) {
                        String dnsName = name.getName().toString();
                        if (!dnsName.matches(sanRegex)) {
                            throw new IllegalArgumentException("A Subject Alternative Name (" + dnsName + ") from CSR does not match the template's validation rules.");
                        }
                    }
                }
            }
        }
    }

    private ASN1Encodable buildKeyUsage(String keyUsageString) {
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

    private ASN1Encodable buildExtendedKeyUsage(String extendedKeyUsageString) {
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

}
