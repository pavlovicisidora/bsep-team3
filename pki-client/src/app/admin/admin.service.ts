import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable } from 'rxjs';
import { environment } from '../environment';

@Injectable({
  providedIn: 'root'
})
export class AdminService {
  private apiUrl = environment.apiUrl;

  constructor(private http: HttpClient) { }

  createCaUser(userData: any): Observable<any> {
    return this.http.post(`${this.apiUrl}/api/admin/ca-user`, userData, { responseType: 'text' });
  }
}