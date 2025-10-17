import { Component, OnInit } from '@angular/core';
import { AbstractControl, FormBuilder, FormGroup, ValidationErrors, ValidatorFn, Validators } from '@angular/forms';
import { CertificateManagementService, Issuer } from '../certificate-management.service'; // PAŽNJA: Proverite putanju

@Component({
  selector: 'app-ee-certificate',
  templateUrl: './ee-certificate.component.html',
  styleUrls: ['./ee-certificate.component.css']
})
export class EeCertificateComponent implements OnInit {

  eeCertForm!: FormGroup;
  issuers: Issuer[] = [];
  selectedFile: File | null = null;
  isLoading = true;

  constructor(
    private fb: FormBuilder,
    private certificateService: CertificateManagementService
  ) {}

  ngOnInit(): void {
    this.initializeForm();
    this.loadIssuers();
  }

  private initializeForm(): void {
    this.eeCertForm = this.fb.group({
      issuerSerialNumber: [null, Validators.required],
      validTo: ['', [Validators.required, this.dateInFutureValidator()]],
    }, {
      // Validator koji proverava da li je željeni datum isteka pre datuma isteka izdavaoca
      validators: this.issuerExpiryValidator()
    });
  }

  private loadIssuers(): void {
    this.isLoading = true;
    this.certificateService.getIssuers().subscribe({
      next: (data) => {
        this.issuers = data;
        this.isLoading = false;
      },
      error: (err) => {
        console.error("Greška pri učitavanju izdavalaca:", err);
        alert("Nije moguće učitati listu izdavalaca.");
        this.isLoading = false;
      }
    });
  }

  // Metoda koja se poziva kada korisnik odabere fajl
  onFileSelected(event: Event): void {
    const element = event.currentTarget as HTMLInputElement;
    let fileList: FileList | null = element.files;
    if (fileList && fileList.length > 0) {
      this.selectedFile = fileList[0];
    } else {
      this.selectedFile = null;
    }
  }

  onSubmit(): void {
    // Proveravamo i validnost forme i da li je fajl odabran
    if (this.eeCertForm.invalid || !this.selectedFile) {
      this.eeCertForm.markAllAsTouched();
      // Možemo dodati i posebnu poruku ako fajl nije odabran
      if (!this.selectedFile) {
        alert('Morate odabrati .csr fajl.');
      }
      return;
    }

    const formData = this.eeCertForm.value;
    const validToISO = new Date(formData.validTo).toISOString();

    this.certificateService.createCertificateRequest(
      formData.issuerSerialNumber,
      validToISO,
      this.selectedFile
    ).subscribe({
      next: (response) => {
        alert('Zahtev za sertifikat je uspešno poslat!');
        this.eeCertForm.reset();
        this.selectedFile = null;
      },
      error: (error) => {
        const errorMessage = error.error?.message || error.message || 'Došlo je do nepoznate greške.';
        alert(`Greška: ${errorMessage}`);
      }
    });
  }

  // --- VALIDATORI ---

  isControlInvalid(controlName: string): boolean {
    const control = this.eeCertForm.get(controlName);
    return !!control && control.invalid && (control.dirty || control.touched);
  }

  private dateInFutureValidator(): ValidatorFn {
    return (control: AbstractControl): ValidationErrors | null => {
      if (!control.value) return null;
      return new Date(control.value) <= new Date() ? { dateNotInFuture: true } : null;
    };
  }

  private issuerExpiryValidator(): ValidatorFn {
    return (formGroup: AbstractControl): ValidationErrors | null => {
      const issuerControl = formGroup.get('issuerSerialNumber');
      const validToControl = formGroup.get('validTo');

      if (!issuerControl?.value || !validToControl?.value) return null;

      const selectedIssuer = this.issuers.find(i => i.serialNumber === issuerControl.value);
      if (!selectedIssuer || !selectedIssuer.validTo) return null;

      const requestedExpiry = new Date(validToControl.value);
      const issuerExpiry = new Date(selectedIssuer.validTo);

      if (requestedExpiry > issuerExpiry) {
        validToControl.setErrors({ ...(validToControl.errors || {}), issuerWillExpire: true });
        return { issuerWillExpire: true };
      }
      return null;
    };
  }
}