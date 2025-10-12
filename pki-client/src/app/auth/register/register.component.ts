import { Component, OnInit } from '@angular/core';
import { FormBuilder, FormGroup, Validators } from '@angular/forms';
import { ZXCVBNResult } from 'zxcvbn';
import { AuthService } from '../auth.service';
import * as zxcvbn from 'zxcvbn';

export function passwordMatchValidator(group: FormGroup) {
  const password = group.get('password')?.value;
  const confirmPassword = group.get('confirmPassword')?.value;
  return password === confirmPassword ? null : { mismatch: true };
}

@Component({
  selector: 'app-register',
  templateUrl: './register.component.html',
  styleUrls: ['./register.component.css']
})
export class RegisterComponent implements OnInit {
  registerForm!: FormGroup;
  passwordStrength: { score: number; text: string; color: string } = { score: 0, text: '', color: '' };
  
  isLoading = false;
  successMessage = '';
  errorMessage = '';

  constructor(private fb: FormBuilder, private authService: AuthService) {}

  ngOnInit(): void {
    this.registerForm = this.fb.group({
      firstName: ['', Validators.required],
      lastName: ['', Validators.required],
      organization: ['', Validators.required],
      email: ['', [Validators.required, Validators.email]],
      password: ['', [
        Validators.required, 
        Validators.minLength(8),
        Validators.pattern(/^(?=.*[0-9])(?=.*[a-z])(?=.*[A-Z])(?=.*[@#$%^&+=!])(?=\S+$).*$/)
      ]],
      confirmPassword: ['', Validators.required]
    }, { validators: passwordMatchValidator }); 
  }

  onPasswordInput(event: any): void {
    const password = event.target.value;
    if (!password) {
      this.passwordStrength = { score: 0, text: '', color: '' };
      return;
    }
    const result: ZXCVBNResult = zxcvbn(password);
    this.updateStrengthMeter(result.score);
  }

  onSubmit(): void {
    if (this.registerForm.invalid) {
      this.registerForm.markAllAsTouched(); 
      return;
    }

    this.isLoading = true;
    this.successMessage = '';
    this.errorMessage = '';

    const registrationData = this.registerForm.value;

    this.authService.register(registrationData).subscribe({
      next: (response) => {
        this.isLoading = false;
        this.successMessage = 'Registration successful. Please check your email to activate your account.';
        this.registerForm.reset();
      },
      error: (err) => {
        this.isLoading = false;
        this.errorMessage = err.error?.message || 'An error occurred during registration.';
      }
    });
  }

  private updateStrengthMeter(score: number): void {
    this.passwordStrength.score = score;
    const textMap = ['Very weak', 'Weak', 'Good', 'Strong', 'Very strong'];
    const colorMap = ['red', 'orange', 'yellow', 'lightgreen', 'green'];
    this.passwordStrength.text = textMap[score];
    this.passwordStrength.color = colorMap[score];
  }
}
