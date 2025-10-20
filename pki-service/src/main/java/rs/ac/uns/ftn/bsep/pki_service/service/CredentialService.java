package rs.ac.uns.ftn.bsep.pki_service.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import rs.ac.uns.ftn.bsep.pki_service.dto.*;
import rs.ac.uns.ftn.bsep.pki_service.exception.NotFoundException;
import rs.ac.uns.ftn.bsep.pki_service.model.Credential;
import rs.ac.uns.ftn.bsep.pki_service.model.SharedPassword;
import rs.ac.uns.ftn.bsep.pki_service.model.User;
import rs.ac.uns.ftn.bsep.pki_service.repository.CredentialRepository;
import rs.ac.uns.ftn.bsep.pki_service.repository.SharedPasswordRepository;
import rs.ac.uns.ftn.bsep.pki_service.repository.UserRepository;

import java.nio.file.AccessDeniedException;
import java.util.List;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
@Slf4j
public class CredentialService {

    private final CredentialRepository credentialRepository;
    private final SharedPasswordRepository sharedPasswordRepository;
    private final UserRepository userRepository;

    @Transactional
    public void createCredential(CreateCredentialRequestDto dto, User currentUser) {

        log.info("User {} is creating a new credential for site {}", currentUser.getUsername(), dto.getSiteName());

        Credential credential = new Credential();
        credential.setOwner(currentUser);

        credential.setSiteName(dto.getSiteName());
        credential.setSiteUsername(dto.getUsername());
        Credential savedCredential = credentialRepository.save(credential);

        SharedPassword sharedPassword = new SharedPassword();
        sharedPassword.setCredential(savedCredential);
        sharedPassword.setUser(currentUser);
        sharedPassword.setCreatedBy(currentUser);

        sharedPassword.setEncryptedPassword(dto.getEncryptedPassword());
        sharedPasswordRepository.save(sharedPassword);

        log.info("Successfully created credential with ID {} for user {}", savedCredential.getId(), currentUser.getUsername());
    }

    @Transactional(readOnly = true)
    public List<CredentialResponseDto> getCredentialsForUser(User currentUser) {
        log.debug("Fetching credentials for user {}", currentUser.getUsername());
        List<SharedPassword> sharedPasswords = sharedPasswordRepository.findAllByUser(currentUser);

        return sharedPasswords.stream()
                .map(sp -> new CredentialResponseDto(
                        sp.getCredential().getId(),
                        sp.getCredential().getSiteName(),
                        sp.getCredential().getSiteUsername(),
                        sp.getCredential().getCreatedAt(),
                        sp.getCredential().getOwner().getEmail() 
                ))
                .collect(Collectors.toList());
    }

    @Transactional(readOnly = true)
    public EncryptedPasswordResponseDto getEncryptedPassword(Long credentialId, User currentUser) {
        log.debug("User {} fetching encrypted password for credential ID {}", currentUser.getUsername(), credentialId);
        Credential credential = credentialRepository.findById(credentialId)
                .orElseThrow(() -> new NotFoundException("Credential not found with ID: " + credentialId));

        SharedPassword sharedPassword = sharedPasswordRepository.findByCredentialAndUser(credential, currentUser)
                .orElseThrow(() -> new NotFoundException("Password not found for this user and credential."));

        return new EncryptedPasswordResponseDto(sharedPassword.getEncryptedPassword());
    }

    @Transactional
    public void shareCredential(Long credentialId, ShareCredentialRequestDto dto, User ownerUser) throws AccessDeniedException {

        log.info("User {} is sharing credential ID {} with user email {}", ownerUser.getUsername(), credentialId, dto.getShareWithUserEmail());

        Credential credential = credentialRepository.findById(credentialId)
                .orElseThrow(() -> new NotFoundException("Credential not found with ID: " + credentialId));

        // Provera vlasništva ostaje ista
        if (!credential.getOwner().getId().equals(ownerUser.getId())) {
            log.warn("SECURITY ALERT: User {} attempted to share a credential they do not own (ID: {})", ownerUser.getUsername(), credentialId);
            throw new AccessDeniedException("Only the owner can share this credential.");
        }


        // Pronalazimo korisnika po EMAILU, a ne po ID-u.
        User userToShareWith = userRepository.findByEmail(dto.getShareWithUserEmail())
                .orElseThrow(() -> new NotFoundException("User to share with not found with email: " + dto.getShareWithUserEmail()));


        // Dodatna provera: Ne možete deliti sami sa sobom
        if (userToShareWith.getId().equals(ownerUser.getId())) {
            throw new IllegalArgumentException("You cannot share a credential with yourself.");
        }

        SharedPassword newSharedPassword = new SharedPassword();
        newSharedPassword.setCredential(credential);
        newSharedPassword.setUser(userToShareWith);
        newSharedPassword.setEncryptedPassword(dto.getEncryptedPasswordForUser());
        newSharedPassword.setCreatedBy(ownerUser);
        sharedPasswordRepository.save(newSharedPassword);

        log.info("Successfully shared credential ID {} with user {}", credentialId, userToShareWith.getUsername());
    }
}