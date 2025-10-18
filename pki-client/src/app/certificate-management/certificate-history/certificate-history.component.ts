import { Component, OnInit } from '@angular/core';
import { CertificateManagementService, CertificateRequestResponse } from '../certificate-management.service';

@Component({
  selector: 'app-certificate-history',
  templateUrl: './certificate-history.component.html',
  styleUrls: ['./certificate-history.component.css']
})
export class CertificateHistoryComponent implements OnInit {

  myRequests: CertificateRequestResponse[] = [];
  isLoading = true;
  errorMessage: string | null = null;

  constructor(private certificateService: CertificateManagementService) { }

  ngOnInit(): void {
    this.loadMyRequestHistory();
  }

  loadMyRequestHistory(): void {
    this.isLoading = true;
    this.errorMessage = null;
    this.certificateService.getMyRequests().subscribe({
      next: (data) => {
        this.myRequests = data;
        this.isLoading = false;
      },
      error: (err) => {
        this.errorMessage = 'Greška pri učitavanju istorije zahteva.';
        console.error(err);
        this.isLoading = false;
      }
    });
  }

  
  getStatusClass(status: 'PENDING' | 'APPROVED' | 'REJECTED'): string {
    switch (status) {
      case 'PENDING': return 'status-pending';
      case 'APPROVED': return 'status-approved';
      case 'REJECTED': return 'status-rejected';
      default: return '';
    }
  }
}