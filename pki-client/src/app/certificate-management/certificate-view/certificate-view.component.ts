import { Component, OnInit } from '@angular/core';
import { CertificateManagementService, CertificateDetailsDto } from '../certificate-management.service'; // PAŽNJA: Proverite putanju
import { MatDialog } from '@angular/material/dialog';
import { MatSnackBar } from '@angular/material/snack-bar';
import { RevokeDialogComponent } from '../revoke-dialog/revoke-dialog.component';
import saveAs from 'file-saver';

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

  constructor(private certificateService: CertificateManagementService,
    public dialog: MatDialog,
    private snackBar: MatSnackBar ) {}

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

  openRevokeDialog(certificate: CertificateDetailsDto): void {
    const dialogRef = this.dialog.open(RevokeDialogComponent, {
      width: '400px',
      data: { commonName: certificate.commonName, serialNumber: certificate.serialNumber }
    });

    dialogRef.afterClosed().subscribe(result => {
      // 'result' će biti razlog koji je korisnik izabrao u dialogu
      if (result) {
        this.certificateService.revokeCertificate(certificate.serialNumber, result).subscribe({
          next: (responseMessage) => {
            this.snackBar.open(responseMessage, 'Close', { duration: 3000, panelClass: ['success-snackbar'] });
            // Osveži listu sertifikata da se vidi promena
            this.loadCertificates(); 
          },
          error: (err) => {
            this.snackBar.open(err.error || 'Failed to revoke certificate.', 'Close', { duration: 3000, panelClass: ['error-snackbar'] });
          }
        });
      }
    });
  }

  onDownloadCrl(alias: string): void {
    if (!alias) {
      this.snackBar.open('Certificate alias is missing.', 'Close', { duration: 3000, panelClass: ['error-snackbar'] });
      return;
    }

    this.certificateService.downloadCrl(alias).subscribe({
      next: (blob) => {
        saveAs(blob, `${alias}.crl`);
        this.snackBar.open('CRL download started.', 'Close', { duration: 3000, panelClass: ['success-snackbar'] });
      },
      error: (err) => {
        console.error("CRL download error:", err);
        this.snackBar.open('Failed to download CRL.', 'Close', { duration: 3000, panelClass: ['error-snackbar'] });
      }
    });
  }
}
