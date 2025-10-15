import { Injectable } from '@angular/core';
import { HttpClient, HttpParams } from '@angular/common/http';
import { BehaviorSubject, Observable, tap } from 'rxjs';
import { environment } from '../environment';
import { Router } from '@angular/router';
import { jwtDecode } from 'jwt-decode';

export interface ResetPasswordPayload {
  token: string;
  newPassword: string;
  confirmNewPassword: string;
}

@Injectable({
  providedIn: 'root'
})
export class AuthService {
  private apiUrl = environment.apiUrl;
  private tokenKey = 'pki_auth_token';

  private currentUserSubject = new BehaviorSubject<any>(null);
  public currentUser$ = this.currentUserSubject.asObservable();

  constructor(private http: HttpClient, private router: Router) {
    this.loadUserFromToken();
  }

  private loadUserFromToken(): void {
    const token = this.getToken();
    if (token) {
      try {
        const decodedUser = jwtDecode(token);
        this.currentUserSubject.next(decodedUser);
      } catch (error) {
        console.error('Invalid token found, logging out.', error);
        this.logout();
      }
    }
  }

  public get currentUserValue(): any {
    return this.currentUserSubject.value;
  }

  login(credentials: any): Observable<{jwt: string}> {
    return this.http.post<{jwt: string}>(`${this.apiUrl}/api/auth/login`, credentials).pipe(
      tap(response => {
        this.saveToken(response.jwt);
        const decodedUser = jwtDecode(response.jwt);
        this.currentUserSubject.next(decodedUser);
      })
    );
  }

  register(userData: any): Observable<any> {
    return this.http.post(`${this.apiUrl}/api/auth/register`, userData, { responseType: 'text' });
  }

  saveToken(token: string): void {
    localStorage.setItem(this.tokenKey, token);
  }

  getToken(): string | null {
    return localStorage.getItem(this.tokenKey);
  }

  isLoggedIn(): boolean {
    return !!this.getToken() && !!this.currentUserValue;
  }

  logout(): void {
    localStorage.removeItem(this.tokenKey);
    this.currentUserSubject.next(null); 
    this.router.navigate(['/login']);
  }

  forgotPassword(email: string): Observable<string> {
    
    const params = new HttpParams().set('email', email);

    
    const url = `${this.apiUrl}/api/auth/forgot-password`;

    return this.http.post(url, null, { params, responseType: 'text' });
  }

   resetPassword(payload: ResetPasswordPayload): Observable<string> {
    const url = `${this.apiUrl}/api/auth/reset-password`;
    return this.http.post(url, payload, { responseType: 'text' });
  }
}