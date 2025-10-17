package rs.ac.uns.ftn.bsep.pki_service.model.enums;

public enum RequestStatus {
    PENDING,  // Zahtev čeka odobrenje
    APPROVED, // Zahtev je odobren i sertifikat je kreiran
    REJECTED  // Zahtev je odbijen
}
