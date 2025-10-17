import { Injectable } from '@angular/core';
import { HttpClient, HttpParams } from '@angular/common/http';
import { BehaviorSubject, Observable, tap } from 'rxjs';
import { environment } from '../environment';
import { Router } from '@angular/router';
import { jwtDecode } from 'jwt-decode';
import { finalize } from 'rxjs/operators';

export interface ResetPasswordPayload {
  token: string;
  newPassword: string;
  confirmNewPassword: string;
}

interface LoginResponse {
  jwt: string;
  passwordChangeRequired: boolean;

}

@Injectable({
  providedIn: 'root'
})
export class AuthService {
  private apiUrl = environment.apiUrl;
  private tokenKey = 'pki_auth_token';

  private currentUserSubject = new BehaviorSubject<any>(null);
  public currentUser$ = this.currentUserSubject.asObservable();

  private passwordChangeRequiredSubject = new BehaviorSubject<boolean>(false);
  public isPasswordChangeRequired$ = this.passwordChangeRequiredSubject.asObservable();

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

  login(credentials: any): Observable<LoginResponse> {
    return this.http.post<LoginResponse>(`${this.apiUrl}/api/auth/login`, credentials).pipe(
      tap(response => {
        this.saveToken(response.jwt);
        const decodedUser = jwtDecode(response.jwt);
        this.currentUserSubject.next(decodedUser);
        
        this.passwordChangeRequiredSubject.next(response.passwordChangeRequired);
      })
    );
  }

  caUserChangePassword(passwords: any): Observable<any> {
    return this.http.post(`${this.apiUrl}/api/user/change-password`, passwords, { responseType: 'text' }).pipe(
      tap(() => {
        this.passwordChangeRequiredSubject.next(false);
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
    console.log('Pokretanje procesa odjave...');

    // Prvo šaljemo zahtev serveru da obriše sesiju iz baze.
    // Vaš AuthInterceptor će automatski dodati "Authorization" heder.
    this.http.delete(`${this.apiUrl}/api/sessions/logout`).pipe(
      // Operator 'finalize' se izvršava UVEK nakon što se HTTP poziv završi,
      // bez obzira da li je bio uspešan ili ne. Ovo garantuje da će se
      // korisnik uvek odjaviti na frontendu.
      finalize(() => {
        console.log('Server odgovorio. Čišćenje lokalnih podataka...');
        
        // Logika koju ste već imali sada ide ovde:
        localStorage.removeItem(this.tokenKey);
        this.currentUserSubject.next(null); 
        this.passwordChangeRequiredSubject.next(false);
        this.router.navigate(['/login']);
      })
    ).subscribe({
      // Subscribe blok je neophodan da bi se HTTP zahtev uopšte poslao.
      // Ovde možemo dodati logere za lakše debagovanje.
      next: () => console.log('Server je potvrdio brisanje sesije.'),
      error: (err) => console.error('Greška pri odjavi na serveru (korisnik će svejedno biti odjavljen na frontendu):', err)
    });
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