import { Component, OnInit } from '@angular/core';
import { FormBuilder, FormGroup, Validators } from '@angular/forms';
import { Router } from '@angular/router';
import { environment } from 'src/app/environment';
import { AuthService } from '../auth.service';
import { ForgotPasswordDialogComponent } from '../forgot-password-dialog/forgot-password-dialog.component';
import { MatDialog } from '@angular/material/dialog';
import { MatSnackBar } from '@angular/material/snack-bar';

@Component({
  selector: 'app-login',
  templateUrl: './login.component.html',
  styleUrls: ['./login.component.css']
})
export class LoginComponent implements OnInit {
  loginForm!: FormGroup;
  recaptchaSiteKey = environment.recaptchaSiteKey;
  
  isLoading = false;
  errorMessage = '';
  registrationSuccessMessage = '';

  constructor(
    private fb: FormBuilder,
    private authService: AuthService,
    private router: Router,
    public dialog: MatDialog,
    private snackBar: MatSnackBar
  ) {
    const navigation = this.router.getCurrentNavigation();
    this.registrationSuccessMessage = navigation?.extras?.state?.['message'];
  }

  ngOnInit(): void {
    this.loginForm = this.fb.group({
      email: ['', [Validators.required, Validators.email]],
      password: ['', Validators.required],
      recaptchaToken: ['', Validators.required]
    });
  }

  onSubmit(): void {
    if (this.loginForm.invalid) {
      return;
    }

    this.isLoading = true;
    this.errorMessage = '';
    
    this.authService.login(this.loginForm.value).subscribe({
      next: (response) => {
        this.isLoading = false;
        if (response.passwordChangeRequired) {
          this.router.navigate(['/force-password-change']);
        } else {
          this.router.navigate(['/dashboard']); 
        }
      },
      error: (err) => {
        this.isLoading = false;
        this.errorMessage = 'Login failed. Please check your credentials and try again.';
        this.loginForm.get('recaptchaToken')?.reset();
      }
    });
  }

   openForgotPasswordDialog(): void {
    const dialogRef = this.dialog.open(ForgotPasswordDialogComponent, {
      width: '400px',
      data: { email: '' } 
    });

   dialogRef.afterClosed().subscribe(email => {
  // Proveravamo da li je korisnik uneo email (nije kliknuo 'Cancel')
  if (email) {
    this.isLoading = true; // Pokaži spinner dok čekamo odgovor
    
    // Pozivamo metodu iz servisa
    this.authService.forgotPassword(email).subscribe({
      next: (response) => {
        this.isLoading = false; // Sakrij spinner
        // Prikazujemo poruku o uspehu
        // Korišćenje snackbar-a je elegantnije od alert-a
        this.snackBar.open(response, 'Close', {
          duration: 5000, // Poruka traje 5 sekundi
          panelClass: ['success-snackbar'] // Opciono, za stilizovanje
        });
      },
      error: (err) => {
        this.isLoading = false; // Sakrij spinner
        console.error('Error sending password reset link:', err);
        // Prikazujemo generičku poruku o grešci
        this.snackBar.open('An error occurred. Please try again later.', 'Close', {
          duration: 5000,
          panelClass: ['error-snackbar'] // Opciono, za stilizovanje
        });
      }
    });
  }
});
  }
}
