import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable } from 'rxjs';
import { ActiveSession } from './model/model.session';

@Injectable({
  providedIn: 'root'
})
export class SessionManagementService {

  // OBAVEZNO AŽURIRAJTE S VAŠIM API URL-om
  private apiUrl = 'http://localhost:8080/api/sessions'; 

  constructor(private http: HttpClient) { }

  /** Dohvata sve aktivne sesije za ulogovanog korisnika. */
  getSessions(): Observable<ActiveSession[]> {
    return this.http.get<ActiveSession[]>(`${this.apiUrl}/my-sessions`);
  }

  /** Šalje zahtev za opoziv sesije. */
  revokeSession(jti: string): Observable<void> {
    return this.http.delete<void>(`${this.apiUrl}/${jti}`);
  }
}