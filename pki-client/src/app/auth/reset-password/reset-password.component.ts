import { Component, OnInit } from '@angular/core';
import { FormBuilder, FormGroup, Validators } from '@angular/forms';
import { ActivatedRoute, Router } from '@angular/router';
import { MatSnackBar } from '@angular/material/snack-bar';
import { AuthService, ResetPasswordPayload } from 'src/app/auth/auth.service';
import zxcvbn, { ZXCVBNResult } from 'zxcvbn';

// Custom validator za podudaranje lozinki - preuzet iz tvog RegisterComponent
export function passwordMatchValidator(group: FormGroup) {
  const password = group.get('newPassword')?.value; // Prilagođen naziv polja
  const confirmPassword = group.get('confirmNewPassword')?.value; // Prilagođen naziv polja
  return password === confirmPassword ? null : { mismatch: true };
}

@Component({
  selector: 'app-reset-password',
  templateUrl: './reset-password.component.html',
  styleUrls: ['./reset-password.component.css'] // Koristi isti CSS kao za register ili prilagodi
})
export class ResetPasswordComponent implements OnInit {
  resetPasswordForm!: FormGroup;
  token: string | null = null;
  
  // Logika za jačinu lozinke - preuzeto iz tvog RegisterComponent
  passwordStrength: { score: number; text: string; color: string } = { score: 0, text: '', color: '' };
  
  isLoading = false;
  errorMessage = '';

  constructor(
    private fb: FormBuilder, 
    private authService: AuthService, 
    private router: Router,
    private route: ActivatedRoute, // Za čitanje tokena iz URL-a
    private snackBar: MatSnackBar
  ) {}

  ngOnInit(): void {
    // 1. Čitamo token iz query parametara URL-a
    this.token = this.route.snapshot.queryParamMap.get('token');

    // Inicijalizujemo formu
    this.resetPasswordForm = this.fb.group({
      newPassword: ['', [
        Validators.required, 
        Validators.minLength(8),
        // Preuzet regex iz tvog RegisterComponent
        Validators.pattern(/^(?=.*[0-9])(?=.*[a-z])(?=.*[A-Z])(?=.*[@#$%^&+=!\.])(?=\S+$).*$/)
      ]],
      confirmNewPassword: ['', Validators.required]
    }, { validators: passwordMatchValidator }); // Koristimo isti validator
  }

  // Metoda za proveru jačine lozinke - preuzeto iz tvog RegisterComponent
  onPasswordInput(event: any): void {
    const password = event.target.value;
    if (!password) {
      this.passwordStrength = { score: 0, text: '', color: '' };
      return;
    }
    const result: ZXCVBNResult = zxcvbn(password);
    this.updateStrengthMeter(result.score);
  }

  // Pomoćna metoda - preuzeto iz tvog RegisterComponent
  private updateStrengthMeter(score: number): void {
    this.passwordStrength.score = score;
    const textMap = ['Very weak', 'Weak', 'Good', 'Strong', 'Very strong'];
    const colorMap = ['red', 'orange', 'yellow', 'lightgreen', 'green'];
    this.passwordStrength.text = textMap[score];
    this.passwordStrength.color = colorMap[score];
  }

  onSubmit(): void {
    if (this.resetPasswordForm.invalid) {
      this.resetPasswordForm.markAllAsTouched();
      return;
    }
    if (!this.token) {
        this.errorMessage = "Token is missing. Cannot reset password.";
        return;
    }

    this.isLoading = true;
    this.errorMessage = '';

    const payload: ResetPasswordPayload = {
      token: this.token,
      newPassword: this.resetPasswordForm.value.newPassword,
      confirmNewPassword: this.resetPasswordForm.value.confirmNewPassword
    };

    this.authService.resetPassword(payload).subscribe({
      next: (response) => {
        this.isLoading = false;
        this.snackBar.open(response, 'Close', { duration: 7000 });
        this.router.navigate(['/login']);
      },
      error: (err) => {
        this.isLoading = false;
        this.errorMessage = err.error || 'An error occurred. The token might be invalid or expired.';
      }
    });
  }
}