import { Component, OnInit } from '@angular/core';
import { FormBuilder, FormGroup, Validators, FormArray, FormControl } from '@angular/forms';
import { Router } from '@angular/router';
import { TemplateService } from '../templates.service';
import { CertificateManagementService, Issuer } from 'src/app/certificate-management/certificate-management.service';

@Component({
  selector: 'app-template-form',
  templateUrl: './template-form.component.html',
  styleUrls: ['./template-form.component.css']
})
export class TemplateFormComponent implements OnInit {
  templateForm: FormGroup;
  issuers: Issuer[] = [];
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

  constructor(
    private fb: FormBuilder,
    private templateService: TemplateService,
    private certificateService: CertificateManagementService, 
    private router: Router
  ) {
    this.templateForm = this.fb.group({
      name: ['', Validators.required],
      issuerSerialNumber: ['', Validators.required],
      commonNameRegex: ['.*\\.yourdomain\\.com', Validators.required],
      subjectAlternativeNamesRegex: [''],
      timeToLiveDays: [365, [Validators.required, Validators.min(1)]],
      keyUsage: this.fb.array([]),
      extendedKeyUsage: this.fb.array([])
    });
  }

  ngOnInit(): void {
    this.certificateService.getIssuers().subscribe(data => {
      this.issuers = data;
    });
  }

  onKeyUsageChange(event: any) {
    const array: FormArray = this.templateForm.get('keyUsage') as FormArray;
    if (event.target.checked) {
      array.push(new FormControl(event.target.value));
    } else {
      const index = array.controls.findIndex(x => x.value === event.target.value);
      array.removeAt(index);
    }
  }

  onExtendedKeyUsageChange(event: any) {
    const array: FormArray = this.templateForm.get('extendedKeyUsage') as FormArray;
    if (event.target.checked) {
      array.push(new FormControl(event.target.value));
    } else {
      const index = array.controls.findIndex(x => x.value === event.target.value);
      array.removeAt(index);
    }
  }

  onSubmit(): void {
    if (this.templateForm.invalid) {
      return;
    }
    this.templateService.createTemplate(this.templateForm.value).subscribe({
      next: () => {
        console.log('Template created successfully');
        this.router.navigate(['/templates']);
      },
      error: (err) => console.error('Failed to create template', err)
    });
  }
}
