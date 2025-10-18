import { Component, OnInit } from '@angular/core';
import { AbstractControl, FormBuilder, FormGroup, ValidationErrors, ValidatorFn, Validators } from '@angular/forms';
import { CertificateManagementService, CreateRootCertificateDto } from '../certificate-management.service'; // PAŽNJA: Proverite putanju


export function notInPastValidator(): ValidatorFn {
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


export function dateRangeValidator(fromControlName: string, toControlName: string): ValidatorFn {
    return (formGroup: AbstractControl): ValidationErrors | null => {
      const fromControl = formGroup.get(fromControlName);
      const toControl = formGroup.get(toControlName);
  
      if (fromControl && toControl && fromControl.value && toControl.value) {
        const fromDate = new Date(fromControl.value);
        const toDate = new Date(toControl.value);
  
        if (toDate <= fromDate) {
          
          toControl.setErrors({ ...toControl.errors, dateRangeInvalid: true });
          return { dateRangeInvalid: true };
        }
      }
      return null;
    };
  }


@Component({
  selector: 'app-root-certificate',
  templateUrl: './root-certificate.component.html',
  styleUrls: ['./root-certificate.component.css']
})
export class RootCertificateComponent implements OnInit {

  certificateForm!: FormGroup;

  constructor(
    private fb: FormBuilder,
    private certificateService: CertificateManagementService
  ) {}

  ngOnInit(): void {
    this.certificateForm = this.fb.group({
      commonName: ['', Validators.required],
      organization: ['', Validators.required],
      organizationalUnit: ['', Validators.required],
      country: ['', [Validators.required, Validators.pattern(/^[A-Z]{2}$/)]],
      email: ['', [Validators.required, Validators.email]],
     
      validFrom: ['', [Validators.required]],
      validTo: ['', [Validators.required]],
    }, {
        
        validators: dateRangeValidator('validFrom', 'validTo')
    });
  }

  isControlInvalid(controlName: string): boolean {
    const control = this.certificateForm.get(controlName);
    return !!control && control.invalid && (control.dirty || control.touched);
  }

  onSubmit(): void {
    if (this.certificateForm.invalid) {
      this.certificateForm.markAllAsTouched();
      return;
    }

    const formData = this.certificateForm.value;

    const certificateDto: CreateRootCertificateDto = {
      ...formData,
      validFrom: `${formData.validFrom}:00`,
      validTo: `${formData.validTo}:00`,
    };

    this.certificateService.createRootCertificate(certificateDto).subscribe({
      next: (response) => {
        console.log('Root sertifikat je uspešno kreiran!', response);
        alert('Uspešno ste kreirali Root sertifikat!');
        this.certificateForm.reset();
      },
      error: (error) => {
        console.error('Došlo je do greške prilikom kreiranja sertifikata:', error);
        alert(`Greška: ${error.error || 'Dogodila se nepoznata greška na serveru.'}`);
      }
    });
  }
}