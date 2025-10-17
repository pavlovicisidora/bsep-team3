package rs.ac.uns.ftn.bsep.pki_service.service;

import lombok.extern.slf4j.Slf4j; // <-- DODATO
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.mail.MailException; // <-- DODATO
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;

@Service
@Slf4j // <-- DODATO
public class EmailService {

    private final JavaMailSender mailSender;

    @Autowired
    public EmailService(JavaMailSender mailSender) {
        this.mailSender = mailSender;
    }

    @Async
    public void sendActivationEmail(String to, String token) {
        log.info("Preparing to send activation email to: {}", to);
        try {
            SimpleMailMessage message = new SimpleMailMessage();
            message.setTo(to);
            message.setSubject("Account activation - PKI Service");

            String activationUrl = "http://localhost:8080/api/auth/activate?token=" + token;

            message.setText("Dear Sir,\n\nThank you for registering. Please activate your account by clicking on the link below:\n\n"
                    + activationUrl + "\n\nThe link will expire in 15 minutes.\n\nRegards,\nThe PKI Team");

            mailSender.send(message);
            log.info("Successfully sent activation email to: {}", to);
        } catch (MailException e) {
            // Logujemo kao grešku jer neuspelo slanje mejla može biti kritično za korisnika.
            log.error("Failed to send activation email to: {}. Reason: {}", to, e.getMessage());
        }
    }

    @Async
    public void sendCaUserCredentials(String to, String rawPassword) {
        log.info("Preparing to send CA user credentials to: {}", to);
        try {
            SimpleMailMessage message = new SimpleMailMessage();
            message.setTo(to);
            message.setSubject("An account has been created for you on the PKI Service");

            message.setText(String.format(
                    "Hello,\n\nAn administrator has created an account for you to access the PKI Service.\n\n" +
                            "Your credentials for the first login are:\n" +
                            "Username: %s\n" +
                            "Temporary password: %s\n\n" +
                            "After your first login, the system will require you to set a new password.\n\n" +
                            "Regards,\nThe PKI Team",
                    to, rawPassword
            ));

            mailSender.send(message);
            log.info("Successfully sent CA user credentials email to: {}", to);
        } catch (MailException e) {
            log.error("Failed to send CA user credentials email to: {}. Reason: {}", to, e.getMessage());
        }
    }


    @Async
    public void sendPasswordResetEmail(String to, String token) {
        log.info("Preparing to send password reset email to: {}", to);
        try {
            SimpleMailMessage message = new SimpleMailMessage();
            message.setTo(to);
            message.setSubject("Oporavak lozinke - PKI Servis");

            String resetUrl = "http://localhost:4200/reset-password?token=" + token;

            message.setText("Poštovani,\n\nZatražili ste oporavak lozinke za Vaš nalog. Kliknite na link ispod kako biste postavili novu lozinku:\n\n"
                    + resetUrl + "\n\nUkoliko niste Vi zatražili oporavak, molimo Vas da ignorišete ovu poruku.\n\nLink ističe za 15 minuta.\n\nSrdačan pozdrav,\nVaš PKI Tim");

            mailSender.send(message);
            log.info("Successfully sent password reset email to: {}", to);
        } catch (MailException e) {
            log.error("Failed to send password reset email to: {}. Reason: {}", to, e.getMessage());
        }
    }
}