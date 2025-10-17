import { Component, OnInit } from '@angular/core';
import { AbstractControl, FormBuilder, FormGroup, ValidationErrors, ValidatorFn, Validators } from '@angular/forms';
import { forkJoin } from 'rxjs';

// Uvezite sve potrebne servise i interfejse
import {
  CertificateManagementService,
  CreateIntermediateCertificateDto,
  Issuer,
  CaUser
} from '../certificate-management.service'; // PAŽNJA: Proverite putanju do servisa!
import { AuthService } from 'src/app/auth/auth.service';


// ------------------- VALIDATORI DATUMA (SPOJENI I ISPRAVLJENI) -------------------

function notInPastValidator(): ValidatorFn {
  return (control: AbstractControl): ValidationErrors | null => {
    if (!control.value) {
      return null;
    }
    const selectedDate = new Date(control.value);
    const now = new Date();
    now.setSeconds(0, 0);
    return selectedDate < now ? { dateInPast: true } : null;
  };
}

/**
 * ISPRAVLJENA VERZIJA VALIDATORA
 * Proverava da li je 'validTo' datum nakon 'validFrom' datuma.
 */
function dateRangeValidator(fromControlName: string, toControlName: string): ValidatorFn {
    return (formGroup: AbstractControl): ValidationErrors | null => {
      const fromControl = formGroup.get(fromControlName);
      const toControl = formGroup.get(toControlName);
  
      if (fromControl && toControl && fromControl.value && toControl.value) {
        const fromDate = new Date(fromControl.value);
        const toDate = new Date(toControl.value);
  
        if (toDate <= fromDate) {
          // ISPRAVKA 1: Bezbedno dodavanje nove greške, čuvajući postojeće.
          const existingErrors = toControl.errors || {};
          toControl.setErrors({ ...existingErrors, dateRangeInvalid: true });
          return { dateRangeInvalid: true };
        }
      }
      
      // ISPRAVKA 2: Bezbedno uklanjanje greške ako postoji.
      if (toControl && toControl.hasError('dateRangeInvalid')) {
        // Kreiramo kopiju postojećih grešaka
        const errors = { ...toControl.errors };
        // Brišemo našu grešku iz kopije
        delete errors['dateRangeInvalid'];
        
        // Ako nema više grešaka, postavljamo errors na null, inače postavljamo ažurirani objekat.
        if (Object.keys(errors).length === 0) {
            toControl.setErrors(null);
        } else {
            toControl.setErrors(errors);
        }
      }

      return null;
    };
}


// ------------------- KOMPONENTA -------------------

@Component({
  selector: 'app-intermediate-certificate',
  templateUrl: './intermediate-certificate.component.html',
  styleUrls: ['./intermediate-certificate.component.css']
})
export class IntermediateCertificateComponent implements OnInit {

  intermediateCertForm!: FormGroup;
  issuers: Issuer[] = [];
  users: CaUser[] = [];
  isAdmin = false;
  isLoading = true;

  constructor(
    private fb: FormBuilder,
    private certificateService: CertificateManagementService,
    private authService: AuthService
  ) {}

  ngOnInit(): void {
    this.isAdmin = this.authService.currentUserValue.role === 'ADMIN';
    this.initializeForm(); // Inicijalizuj formu pre učitavanja podataka
    this.loadInitialData();
  }

  private initializeForm(): void {
    this.intermediateCertForm = this.fb.group({
      issuerSerialNumber: [null, Validators.required],
      commonName: ['', Validators.required],
      organization: ['', Validators.required],
      organizationalUnit: ['', Validators.required],
      country: ['', [Validators.required, Validators.pattern(/^[A-Z]{2}$/)]],
      email: ['', [Validators.required, Validators.email]],
      validFrom: ['', [Validators.required, notInPastValidator()]],
      validTo: ['', [Validators.required, notInPastValidator()]],
      ownerId: [null, this.isAdmin ? Validators.required : []]
    }, {
      validators: dateRangeValidator('validFrom', 'validTo')
    });
  }

  private loadInitialData(): void {
    this.isLoading = true;
    const issuers$ = this.certificateService.getIssuers();

    if (this.isAdmin) {
      const users$ = this.certificateService.getAllCaUsers();
      forkJoin([issuers$, users$]).subscribe({
        next: ([issuers, users]) => {
          this.issuers = issuers;
          this.users = users;
          this.isLoading = false;
        },
        error: (err) => {
          console.error("Greška pri učitavanju podataka za admina:", err);
          alert("Došlo je do greške prilikom učitavanja podataka. Proverite konzolu.");
          this.isLoading = false;
        }
      });
    } else {
      issuers$.subscribe({
        next: (issuers) => {
          this.issuers = issuers;
          this.isLoading = false;
        },
        error: (err) => {
          console.error("Greška pri učitavanju izdavalaca:", err);
          alert("Došlo je do greške prilikom učitavanja izdavalaca. Proverite konzolu.");
          this.isLoading = false;
        }
      });
    }
  }

  isControlInvalid(controlName: string): boolean {
    const control = this.intermediateCertForm.get(controlName);
    return !!control && control.invalid && (control.dirty || control.touched);
  }

  onSubmit(): void {
    if (this.intermediateCertForm.invalid) {
      this.intermediateCertForm.markAllAsTouched();
      return;
    }

    const formData = this.intermediateCertForm.value;
    const currentUserId = this.authService.currentUserValue.id;

    const certificateDto: CreateIntermediateCertificateDto = {
      ...formData,
      validFrom: `${formData.validFrom}:00`,
      validTo: `${formData.validTo}:00`,
      ownerId: this.isAdmin ? formData.ownerId : currentUserId
    };

    this.certificateService.createIntermediateCertificate(certificateDto).subscribe({
      next: (response) => {
        alert('Intermediate sertifikat je uspešno kreiran!');
        this.intermediateCertForm.reset();
      },
      error: (error) => {
        console.error('Greška:', error);
        const errorMessage = error.error?.message || error.message || 'Došlo je do nepoznate greške.';
        alert(`Greška: ${errorMessage}`);
      }
    });
  }
}