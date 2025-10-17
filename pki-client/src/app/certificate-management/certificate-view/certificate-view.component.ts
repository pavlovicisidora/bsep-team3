import { Component, OnInit } from '@angular/core';
import { CertificateManagementService, CertificateDetailsDto } from '../certificate-management.service'; // PAŽNJA: Proverite putanju

@Component({
  selector: 'app-certificate-view',
  templateUrl: './certificate-view.component.html',
  styleUrls: ['./certificate-view.component.css']
})
export class CertificateViewComponent implements OnInit {

  // Niz u kojem čuvamo sve sertifikate dobijene sa servera
  certificates: CertificateDetailsDto[] = [];
  
  // Flag za prikaz "loading" poruke dok se čeka odgovor sa servera
  isLoading = true;

  constructor(private certificateService: CertificateManagementService) {}

  // ngOnInit se izvršava odmah nakon što se komponenta kreira
  ngOnInit(): void {
    this.loadCertificates();
  }

  // Metoda za dobavljanje podataka
  loadCertificates(): void {
    this.isLoading = true;
    this.certificateService.getAllCertificates().subscribe({
      next: (data) => {
        // Kada podaci stignu, upisujemo ih u naš niz
        this.certificates = data;
        // Gasimo "loading" poruku
        this.isLoading = false;
      },
      error: (err) => {
        console.error("Greška pri učitavanju sertifikata:", err);
        alert("Nije moguće učitati listu sertifikata. Proverite konzolu za detalje.");
        // Gasimo "loading" poruku čak i ako je greška
        this.isLoading = false;
      }
    });
  }
}