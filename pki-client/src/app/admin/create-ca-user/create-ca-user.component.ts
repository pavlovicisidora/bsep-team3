import { Component, OnInit } from '@angular/core';
import { FormBuilder, FormGroup, Validators } from '@angular/forms';
import { MatSnackBar } from '@angular/material/snack-bar'; 
import { AdminService } from '../admin.service';

@Component({
  selector: 'app-create-ca-user',
  templateUrl: './create-ca-user.component.html',
  styleUrls: ['./create-ca-user.component.css']
})
export class CreateCaUserComponent implements OnInit {
  caUserForm!: FormGroup;
  isLoading = false;

  constructor(
    private fb: FormBuilder,
    private adminService: AdminService,
    private snackBar: MatSnackBar
  ) { }

  ngOnInit(): void {
    this.caUserForm = this.fb.group({
      firstName: ['', Validators.required],
      lastName: ['', Validators.required],
      organization: ['', Validators.required],
      email: ['', [Validators.required, Validators.email]]
    });
  }

  onSubmit(): void {
    if (this.caUserForm.invalid) {
      return;
    }

    this.isLoading = true;
    
    this.adminService.createCaUser(this.caUserForm.value).subscribe({
      next: (responseMessage) => {
        this.isLoading = false;
        this.snackBar.open(responseMessage, 'Close', { 
          duration: 5000, 
          panelClass: ['success-snackbar'] 
        });
        this.caUserForm.reset();
        Object.keys(this.caUserForm.controls).forEach(key => {
          this.caUserForm.get(key)?.setErrors(null);
        });
      },
      error: (err) => {
        this.isLoading = false;
        this.snackBar.open(err.error || 'An error occurred.', 'Close', { 
          duration: 5000,
          panelClass: ['error-snackbar']
        });
      }
    });
  }
}