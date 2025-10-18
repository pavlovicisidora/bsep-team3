package rs.ac.uns.ftn.bsep.pki_service.service;

import lombok.RequiredArgsConstructor;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import rs.ac.uns.ftn.bsep.pki_service.dto.TemplateCreateDto;
import rs.ac.uns.ftn.bsep.pki_service.model.CertificateData;
import rs.ac.uns.ftn.bsep.pki_service.model.Template;
import rs.ac.uns.ftn.bsep.pki_service.model.User;
import rs.ac.uns.ftn.bsep.pki_service.model.enums.UserRole;
import rs.ac.uns.ftn.bsep.pki_service.repository.CertificateRepository;
import rs.ac.uns.ftn.bsep.pki_service.repository.TemplateRepository;
import rs.ac.uns.ftn.bsep.pki_service.repository.UserRepository;

import java.math.BigInteger;
import java.util.List;

@Service
@RequiredArgsConstructor
public class TemplateService {

    private final TemplateRepository templateRepository;
    private final CertificateRepository certificateRepository;

    public Template createTemplate(TemplateCreateDto dto) {
        User currentUser = (User) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        if (!currentUser.getRole().equals(UserRole.CA_USER)) {
            throw new SecurityException("Only CA users can create templates.");
        }

        CertificateData issuer = certificateRepository
                .findBySerialNumber(new BigInteger(dto.getIssuerSerialNumber()))
                .orElseThrow(() -> new IllegalArgumentException("Issuer not found."));

        if (!issuer.getOwner().getId().equals(currentUser.getId())) {
            throw new SecurityException("You can only create templates for CAs you own.");
        }

        if (!issuer.isCa()) {
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

        return templateRepository.save(template);
    }

    public List<Template> getTemplatesForCurrentUser() {
        User currentUser = (User) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        if (!currentUser.getRole().equals(UserRole.CA_USER)) {
            return List.of();
        }
        return templateRepository.findByOwner(currentUser);
    }

    public void deleteTemplate(Long id) {
        User currentUser = (User) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        Template template = templateRepository.findById(id)
                .orElseThrow(() -> new IllegalArgumentException("Template not found."));

        if (!template.getOwner().getId().equals(currentUser.getId())) {
            throw new SecurityException("You do not have permission to delete this template.");
        }

        templateRepository.delete(template);
    }

}
