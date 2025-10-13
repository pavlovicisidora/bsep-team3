import { Component, OnInit } from '@angular/core';
import { FormBuilder, FormGroup, Validators } from '@angular/forms';
import { Router } from '@angular/router';
import { environment } from 'src/app/environment';
import { AuthService } from '../auth.service';

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
    private router: Router
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
        this.router.navigate(['/dashboard']); 
      },
      error: (err) => {
        this.isLoading = false;
        this.errorMessage = 'Login failed. Please check your credentials and try again.';
        this.loginForm.get('recaptchaToken')?.reset();
      }
    });
  }
}
