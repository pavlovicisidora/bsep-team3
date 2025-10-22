import { Component, OnInit, OnDestroy } from '@angular/core';
import { AbstractControl, FormBuilder, FormGroup, ValidationErrors, ValidatorFn, Validators } from '@angular/forms';
import { CertificateManagementService, Issuer } from '../certificate-management.service'; // PAŽNJA: Proverite putanju
import { Observable, Subscription } from 'rxjs';
import { map } from 'rxjs/operators';
import { AuthService } from 'src/app/auth/auth.service';

@Component({
  selector: 'app-ee-certificate',
  templateUrl: './ee-certificate.component.html',
  styleUrls: ['./ee-certificate.component.css']
})
export class EeCertificateComponent implements OnInit, OnDestroy {

  eeCertForm!: FormGroup;
  issuers: Issuer[] = [];
  selectedFile: File | null = null;
  isLoading = true;

  // Observable promenljive za korišćenje u templejtu sa 'async' pipe-om
  isAdmin$: Observable<boolean>;
  isCaUser$: Observable<boolean>;
  isOrdinaryUser$: Observable<boolean>;

  // Nova promenljiva za čuvanje uloge kao string
  private currentUserRole: string | null = null;
  // Promenljiva za čuvanje pretplate kako bismo je uništili
  private userSubscription!: Subscription;

  constructor(
    private fb: FormBuilder,
    private certificateService: CertificateManagementService,
    private authService: AuthService
  ) {
    this.isAdmin$ = this.authService.currentUser$.pipe(map(user => !!user && user.role === 'ADMIN'));
    this.isCaUser$ = this.authService.currentUser$.pipe(map(user => !!user && user.role === 'CA_USER'));
    this.isOrdinaryUser$ = this.authService.currentUser$.pipe(map(user => !!user && user.role === 'ORDINARY_USER'));
  }

  ngOnInit(): void {
    // Pretplata na korisnika kako bismo uvek imali ažurnu ulogu
    this.userSubscription = this.authService.currentUser$.subscribe(user => {
      // Čuvamo ulogu u lokalnoj promenljivoj
      this.currentUserRole = user ? user.role : null;
    });

    this.initializeForm();
    this.loadIssuers();
  }

  ngOnDestroy(): void {
    // Obavezno uništiti pretplatu da se izbegne curenje memorije
    if (this.userSubscription) {
      this.userSubscription.unsubscribe();
    }
  }

  private initializeForm(): void {
    this.eeCertForm = this.fb.group({
      issuerSerialNumber: [null, Validators.required],
      validTo: ['', [Validators.required, this.dateInFutureValidator()]],
    }, {
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
    if (this.eeCertForm.invalid || !this.selectedFile) {
      this.eeCertForm.markAllAsTouched();
      if (!this.selectedFile) {
        alert('Morate odabrati .csr fajl.');
      }
      return;
    }

    const formData = this.eeCertForm.value;
    const validToISO = new Date(formData.validTo).toISOString();

    // ISPRAVLJENA LOGIKA: Proveravamo vrednost sačuvane uloge
    if (this.currentUserRole === 'ADMIN' || this.currentUserRole === 'CA_USER') {
      console.log('Akcija za ADMIN ili CA_USER korisnika.');
      this.certificateService.createEECertificate(
          formData.issuerSerialNumber,
          validToISO,
          this.selectedFile
        ).subscribe({
          next: () => {
            alert('Uspešno kreiran sertifikat!');
            this.eeCertForm.reset();
            this.selectedFile = null;
          },
          error: (error) => {
            const errorMessage = error.error?.message || error.message || 'Došlo je do nepoznate greške.';
            alert(`Greška: ${errorMessage}`);
          }
        });
    } else if (this.currentUserRole === 'ORDINARY_USER') {
      console.log('Akcija za ORDINARY_USER korisnika.');
      this.certificateService.createCertificateRequest(
          formData.issuerSerialNumber,
          validToISO,
          this.selectedFile
        ).subscribe({
          next: () => {
            alert('Zahtev za sertifikat je uspešno poslat!');
            this.eeCertForm.reset();
            this.selectedFile = null;
          },
          error: (error) => {
            const errorMessage = error.error?.message || error.message || 'Došlo je do nepoznate greške.';
            alert(`Greška: ${errorMessage}`);
          }
        });
    } else {
        // Dobra praksa je obraditi i neočekivane slučajeve
        alert('Nemate odgovarajuću ulogu za izvršavanje ove akcije.');
        console.error('Korisnik nema prepoznatu ulogu:', this.currentUserRole);
    }
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