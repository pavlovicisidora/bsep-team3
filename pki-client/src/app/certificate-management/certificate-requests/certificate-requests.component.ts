import { Component, OnInit } from '@angular/core';
import { CertificateManagementService } from '../certificate-management.service';
// Uvezite ažurirane interfejse
import { CertificateRequestResponse, CsrDetails } from '../certificate-management.service';

// Uvezite potrebne biblioteke za parsiranje
import * as pkijs from 'pkijs';
import * as asn1js from 'asn1js';

@Component({
  selector: 'app-certificate-requests',
  templateUrl: './certificate-requests.component.html',
  styleUrls: ['./certificate-requests.component.css']
})
export class CertificateRequestsComponent implements OnInit {
  
  pendingRequests: CertificateRequestResponse[] = [];
  isLoading = true;
  errorMessage: string | null = null;

  // Za prikaz modala
  selectedRequest: CertificateRequestResponse | null = null;
  // Za prikaz parsiranih podataka u modalu
  parsedCsrDetails: CsrDetails | null = null;
  isParsingCsr = false; // Za prikaz "loading" stanja unutar modala

  constructor(private certificateService: CertificateManagementService) { }

  ngOnInit(): void {
    // Morate imati metodu u servisu koja vraća `CertificateRequestResponse[]`
    // Pretpostavićemo da se zove `getPendingRequestsWithRawCsr`
    this.loadPendingRequests();
  }

  loadPendingRequests(): void {
    this.isLoading = true;
    this.errorMessage = null;
    // Pretpostavka je da getPendingRequests sada vraća tip CertificateRequestResponse[]
    this.certificateService.getPendingRequests().subscribe({
      next: (data: any) => { // Koristimo any za sad, jer vaš servis možda vraća stari tip
        this.pendingRequests = data;
        this.isLoading = false;
      },
      error: (err) => {
        this.errorMessage = 'Greška pri učitavanju zahteva.';
        console.error(err);
        this.isLoading = false;
      }
    });
  }

  

  onApprove(requestId: number): void {
    if (confirm('Da li ste sigurni da želite da odobrite ovaj zahtev?')) {
      this.certificateService.approveRequest(requestId).subscribe({
        next: (response) => {
          // Uspešan odgovor sa servera
          alert('Zahtev je uspešno odobren i sertifikat je kreiran!');
          // Ponovo učitaj listu da bi se odobreni zahtev uklonio
          this.loadPendingRequests();
        },
        error: (err) => {
          // Rukovanje greškom
          const errMsg = err.error?.message || err.message || 'Došlo je do nepoznate greške.';
          alert(`Greška pri odobravanju zahteva: ${errMsg}`);
        }
      });
    }
  }

  
  onReject(requestId: number): void {
    // prompt vraća uneti tekst, prazan string, ili null ako se klikne Cancel
    const reason = prompt('Molimo unesite razlog za odbijanje zahteva:');

    // Proveravamo da li je korisnik kliknuo "Cancel"
    if (reason === null) {
      return; // Korisnik je odustao, ne radimo ništa
    }

    // Proveravamo da li je korisnik kliknuo "OK" ali nije uneo ništa
    if (reason.trim() === '') {
      alert('Razlog za odbijanje je obavezan.');
      return;
    }

    // Ako je sve u redu, šaljemo zahtev
    this.certificateService.rejectRequest(requestId, reason.trim()).subscribe({
      next: () => {
        alert('Zahtev je uspešno odbijen.');
        // Ponovo učitaj listu da bi se odbijeni zahtev uklonio
        this.loadPendingRequests();
      },
      error: (err) => {
        const errMsg = err.error?.message || err.message || 'Došlo je do nepoznate greške.';
        alert(`Greška pri odbijanju zahteva: ${errMsg}`);
      }
    });
  }

  // --- Logika za Modal i PARSIRANJE ---

  async viewCsrDetails(request: CertificateRequestResponse): Promise<void> {
    this.selectedRequest = request;
    this.isParsingCsr = true;
    this.parsedCsrDetails = null; // Resetuj prethodne podatke

    // Dajemo trenutak da se modal iscrta pre nego što počne parsiranje
    setTimeout(async () => {
      try {
        this.parsedCsrDetails = await this.parseCsrPem(request.csrPem);
      } catch (error) {
        console.error("Greška pri parsiranju CSR-a:", error);
        alert("Nije moguće parsirati CSR. Proverite konzolu za greške.");
        this.closeCsrModal();
      } finally {
        this.isParsingCsr = false;
      }
    }, 50);
  }

  closeCsrModal(): void {
    this.selectedRequest = null;
    this.parsedCsrDetails = null;
  }

  private async parseCsrPem(csrPem: string): Promise<CsrDetails> {
    // 1. Očisti PEM string od zaglavlja, podnožja i preloma linija
    const pemClear = csrPem
      .replace(/-----BEGIN CERTIFICATE REQUEST-----/, '')
      .replace(/-----END CERTIFICATE REQUEST-----/, '')
      .replace(/\s/g, '');

    // 2. Pretvori Base64 string u ArrayBuffer
    const decoded = atob(pemClear);
    const buffer = new ArrayBuffer(decoded.length);
    const view = new Uint8Array(buffer);
    for (let i = 0; i < decoded.length; i++) {
      view[i] = decoded.charCodeAt(i);
    }
    
    // 3. Koristi pkijs i asn1js za parsiranje
    const asn1 = asn1js.fromBER(buffer);
    if (asn1.offset === -1) {
      throw new Error("Neuspešno parsiranje ASN.1 strukture.");
    }
    const csr = new pkijs.CertificationRequest({ schema: asn1.result });

    // 4. Izvuci podatke
    const details: CsrDetails = {
      commonName: this.getDnField(csr.subject.typesAndValues, '2.5.4.3'), // OID za Common Name
      organization: this.getDnField(csr.subject.typesAndValues, '2.5.4.10'), // OID za Organization
      organizationalUnit: this.getDnField(csr.subject.typesAndValues, '2.5.4.11'), // OID za Org. Unit
      country: this.getDnField(csr.subject.typesAndValues, '2.5.4.6'), // OID za Country
      email: this.getDnField(csr.subject.typesAndValues, '1.2.840.113549.1.9.1'), // OID za Email
    };

    return details;
  }

  // Pomoćna funkcija za izvlačenje vrednosti iz DN-a
  private getDnField(dnFields: any[], oid: string): string {
    const field = dnFields.find(f => f.type === oid);
    return field ? field.value.valueBlock.value : 'N/A';
  }
}