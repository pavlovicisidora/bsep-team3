package rs.ac.uns.ftn.bsep.pki_service.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;

@Service
public class EmailService {

    private final JavaMailSender mailSender;

    @Autowired
    public EmailService(JavaMailSender mailSender) {
        this.mailSender = mailSender;
    }

    @Async
    public void sendActivationEmail(String to, String token) {
        SimpleMailMessage message = new SimpleMailMessage();
        message.setTo(to);
        message.setSubject("Aktivacija naloga - PKI Servis");

        String activationUrl = "http://localhost:8080/api/auth/activate?token=" + token;

        message.setText("Poštovani,\n\nHvala Vam što ste se registrovali. Molimo Vas da aktivirate Vaš nalog klikom na link ispod:\n\n"
                + activationUrl + "\n\nLink ističe za 15 minuta.\n\nSrdačan pozdrav,\nVaš PKI Tim");

        mailSender.send(message);
    }
}
