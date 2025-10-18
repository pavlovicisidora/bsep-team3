import { Component, Inject } from '@angular/core';
import { MatDialogRef, MAT_DIALOG_DATA } from '@angular/material/dialog';

@Component({
  selector: 'app-revoke-dialog',
  templateUrl: './revoke-dialog.component.html',
})
export class RevokeDialogComponent {
  
  revocationReasons: string[] = [
    'UNSPECIFIED',
    'KEY_COMPROMISE',
    'CA_COMPROMISE',
    'AFFILIATION_CHANGED',
    'SUPERSEDED',
    'CESSATION_OF_OPERATION',
    'CERTIFICATE_HOLD',
    'PRIVILEGE_WITHDRAWN'
  ];
  selectedReason: string = '';

  constructor(
    public dialogRef: MatDialogRef<RevokeDialogComponent>,
    @Inject(MAT_DIALOG_DATA) public data: { commonName: string, serialNumber: string }
  ) {}

  onNoClick(): void {
    this.dialogRef.close();
  }
}
