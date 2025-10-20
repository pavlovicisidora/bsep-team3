import { Component, OnInit } from '@angular/core';
import { AbstractControl, FormArray, FormBuilder, FormControl, FormGroup, ValidationErrors, ValidatorFn, Validators } from '@angular/forms';
import { forkJoin, of } from 'rxjs';

// Uvezite sve potrebne servise i interfejse
import {
  CertificateManagementService,
  CreateIntermediateCertificateDto,
  Issuer,
  CaUser
} from '../certificate-management.service'; // PAŽNJA: Proverite putanju do servisa!
import { AuthService } from 'src/app/auth/auth.service';
import { Template } from 'src/app/template/template.model';


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
  keyUsageOptions = [
    // Najčešće korišćene
    { name: 'Digital Signature', value: 'digitalsignature' },
    { name: 'Key Encipherment', value: 'keyencipherment' },
    { name: 'Data Encipherment', value: 'dataencipherment' },
    { name: 'Non Repudiation', value: 'nonrepudiation' },
    // Specifične za CA
    { name: 'Certificate Sign', value: 'keycertsign' },
    { name: 'CRL Sign', value: 'crlsign' },
    // Manje česte
    { name: 'Key Agreement', value: 'keyagreement' },
    { name: 'Encipher Only', value: 'encipheronly' },
    { name: 'Decipher Only', value: 'decipheronly' },
  ];

  extendedKeyUsageOptions = [
    { name: 'Server Authentication', value: 'serverauth' },
    { name: 'Client Authentication', value: 'clientauth' },
    { name: 'Code Signing', value: 'codesigning' },
    { name: 'Email Protection', value: 'emailprotection' },
    { name: 'Time Stamping', value: 'timestamping' },
    { name: 'OCSP Signing', value: 'ocspsigning' },
  ];


  intermediateCertForm!: FormGroup;
  issuers: Issuer[] = [];
  users: CaUser[] = [];
  templates: Template[] = [];
  isAdmin = false;
  isLoading = true;
  isTemplateSelected = false;

  constructor(
    private fb: FormBuilder,
    private certificateService: CertificateManagementService,
    private authService: AuthService
  ) {}

  ngOnInit(): void {
    this.isAdmin = this.authService.currentUserValue.role === 'ADMIN';
    this.initializeForm(); // Inicijalizuj formu pre učitavanja podataka
    this.loadInitialData();

    this.intermediateCertForm.get('templateId')?.valueChanges.subscribe(templateId => {
      this.isTemplateSelected = !!templateId;
      this.onTemplateSelected(templateId);
    });
  }

  private initializeForm(): void {
    this.intermediateCertForm = this.fb.group({
      issuerSerialNumber: [null, Validators.required],
      commonName: ['', Validators.required],
      organization: ['', Validators.required],
      organizationalUnit: ['', Validators.required],
      country: ['', [Validators.required, Validators.pattern(/^[A-Z]{2}$/)]],
      email: ['', [Validators.required, Validators.email]],
      validFrom: ['', [Validators.required]],
      validTo: ['', [Validators.required]],
      ownerId: [null, this.isAdmin ? Validators.required : []],
      templateId: [null]
    });
  }

  private loadInitialData(): void {
    this.isLoading = true;
    const issuers$ = this.certificateService.getIssuers();
    const templates$ = this.certificateService.getTemplates(); 
    const users$ = this.isAdmin ? this.certificateService.getAllCaUsers() : of(null);

    forkJoin([issuers$, templates$, users$]).subscribe({
      next: ([issuers, templates, users]) => {
        this.issuers = issuers;
        this.templates = templates as unknown as Template[]; 
        if (users) this.users = users;
        this.isLoading = false;
      },
      error: (err) => {
        console.error("Greška pri učitavanju podataka:", err);
        this.isLoading = false;
      }
    });
  }

  private onTemplateSelected(templateId: number | null): void {
    const form = this.intermediateCertForm;
    
    const options = { emitEvent: false };

    form.enable(options); 
    form.get('commonName')?.setValidators([Validators.required]);
    
    if (form.contains('keyUsage')) form.removeControl('keyUsage', options);
    if (form.contains('extendedKeyUsage')) form.removeControl('extendedKeyUsage', options);

    if (!templateId) {
      form.reset({
        templateId: null,
        issuerSerialNumber: null,
        ownerId: this.isAdmin ? null : this.authService.currentUserValue.id,
        organization: '',
      }, options);
      return;
    }
    const selectedTemplate = this.templates.find(t => t.id === Number(templateId));
    if (!selectedTemplate) return;

    console.log("Izabran šablon:", selectedTemplate);
    console.log("Serijski broj issuera iz šablona:", selectedTemplate.issuer.serialNumber);
    
    const issuerForTemplate = this.issuers.find(i => i.serialNumber === selectedTemplate.issuer.serialNumber);
    if (issuerForTemplate) {
      console.log("Pronađen odgovarajući issuer u listi:", issuerForTemplate);
    } else {
      console.warn("UPOZORENJE: Nije pronađen odgovarajući issuer u listi 'this.issuers'. Organizacija neće biti popunjena.");
      console.log("Dostupni issueri:", this.issuers);
    }

    form.patchValue({
      issuerSerialNumber: selectedTemplate.issuer.serialNumber,
      organization: issuerForTemplate?.organization || '',
      country: issuerForTemplate ? this.extractCountryFromDN(selectedTemplate.issuer.subjectDN) : ''
    }, options); 
    const keyUsageValues = this.createCheckboxValues(this.keyUsageOptions, selectedTemplate.keyUsage);
    const extendedKeyUsageValues = this.createCheckboxValues(this.extendedKeyUsageOptions, selectedTemplate.extendedKeyUsage);
    const keyUsageControls = keyUsageValues.map(isSelected => this.fb.control(isSelected));
    const extendedKeyUsageControls = extendedKeyUsageValues.map(isSelected => this.fb.control(isSelected));
    form.addControl('keyUsage', this.fb.array(keyUsageControls), options);
    form.addControl('extendedKeyUsage', this.fb.array(extendedKeyUsageControls), options);
    
    form.get('commonName')?.setValidators([Validators.required, Validators.pattern(selectedTemplate.commonNameRegex)]);

    form.get('issuerSerialNumber')?.disable(options);
    form.get('organization')?.disable(options);
    form.get('country')?.disable(options); 
    form.get('keyUsage')?.disable(options);
    form.get('extendedKeyUsage')?.disable(options);

    form.updateValueAndValidity();
  }
  private extractCountryFromDN(dn: string): string {
    const match = dn.match(/C=([A-Z]{2})/);
    return match ? match[1] : '';
  }

  private createCheckboxValues(options: any[], selectedValuesStr: string): boolean[] {
  if (!selectedValuesStr) {
    return options.map(() => false);
  }

  const selectedValues = selectedValuesStr.toLowerCase().split(',');

  return options.map(option => selectedValues.includes(option.value.toLowerCase()));
}

  get keyUsageControls() {
    return (this.intermediateCertForm.get('keyUsage') as FormArray).controls;
  }
  get extendedKeyUsageControls() {
    return (this.intermediateCertForm.get('extendedKeyUsage') as FormArray).controls;
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

    const formData = this.intermediateCertForm.getRawValue();
    const currentUserId = this.authService.currentUserValue.id;

    const certificateDto: CreateIntermediateCertificateDto = {
      issuerSerialNumber: formData.issuerSerialNumber,
      commonName: formData.commonName,
      organization: formData.organization,
      organizationalUnit: formData.organizationalUnit,
      country: formData.country,
      email: formData.email,
      validFrom: `${formData.validFrom}:00`,
      validTo: `${formData.validTo}:00`,
      ownerId: this.isAdmin ? formData.ownerId : currentUserId,
      templateId: formData.templateId
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

  private updateCheckboxArray(formArray: FormArray, options: any[], selectedValuesStr: string): void {
    formArray.clear(); 
    const selectedValues = selectedValuesStr ? selectedValuesStr.split(',') : [];

    options.forEach(option => {
      const isSelected = selectedValues.includes(option.value);
      const control = new FormControl(isSelected);
      formArray.push(control);
    }); 
  } 
}