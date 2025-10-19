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
    { name: 'Digital Signature', value: 'digitalSignature' },
    { name: 'Key Encipherment', value: 'keyEncipherment' },
    { name: 'Data Encipherment', value: 'dataEncipherment' },
    { name: 'Key Agreement', value: 'keyAgreement' },
    { name: 'Certificate Sign', value: 'keyCertSign' },
    { name: 'CRL Sign', value: 'cRLSign' },
  ];
  extendedKeyUsageOptions = [
    { name: 'Server Authentication', value: 'serverAuth' },
    { name: 'Client Authentication', value: 'clientAuth' },
    { name: 'Code Signing', value: 'codeSigning' },
    { name: 'Email Protection', value: 'emailProtection' },
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
