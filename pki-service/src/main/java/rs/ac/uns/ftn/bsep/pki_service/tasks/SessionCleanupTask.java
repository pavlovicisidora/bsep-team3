package rs.ac.uns.ftn.bsep.pki_service.tasks;

import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;
import rs.ac.uns.ftn.bsep.pki_service.repository.ActiveSessionRepository;

import java.util.Date;

@Component
@RequiredArgsConstructor
public class SessionCleanupTask {

    private static final Logger log = LoggerFactory.getLogger(SessionCleanupTask.class);
    private final ActiveSessionRepository sessionRepository;

    /**
     * Pokreće se svakog sata u :00 minuta, :00 sekundi.
     */
    @Scheduled(cron = "0 0 * * * *")
    @Transactional
    public void cleanupExpiredSessions() {
        log.info("ZAKAZANI ZADATAK: Pokretanje čišćenja isteklih sesija...");

        int deletedCount = sessionRepository.deleteByExpiresAtBefore(new Date());

        if (deletedCount > 0) {
            log.info("ZAKAZANI ZADATAK: Obrisano {} isteklih sesija.", deletedCount);
        } else {
            log.info("ZAKAZANI ZADATAK: Nema isteklih sesija za brisanje.");
        }
    }
}