// src/app/services/password-management.service.ts
import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable } from 'rxjs';


export interface UserPublicKeyDto {
  publicKey: string;
}

export interface CredentialResponseDto {
  id: number;       // ID kredencijala, potreban za akcije (pregledaj, podeli)
  siteName: string; // Ime sajta, za prikaz u tabeli
  username: string; // Korisničko ime, za prikaz u tabeli
  createdAt: Date; // Tip Date će automatski biti parsiran iz JSON stringa
  createdByEmail: string;
}

// DTO za kreiranje
export interface CreateCredentialRequestDto {
  siteName: string;
  username: string;
  encryptedPassword: string;
}


export interface UserDto {
  id: number;
  email: string;
  publicKey: string; 
}

export interface EncryptedPasswordResponseDto {
  encryptedPassword: string;
}

export interface ShareCredentialRequestDto {
  shareWithUserEmail: string;
  encryptedPasswordForUser: string;
}

@Injectable({
  providedIn: 'root'
})
export class PasswordManagementService {
  private readonly baseUrl = 'http://localhost:8080/api';

  constructor(private http: HttpClient) { }

  getCredentials(): Observable<CredentialResponseDto[]> {
    return this.http.get<CredentialResponseDto[]>(`${this.baseUrl}/credentials`);
  }

  
  getCurrentUserPublicKey(): Observable<UserPublicKeyDto> {
    return this.http.get<UserPublicKeyDto>(`${this.baseUrl}/user/me/public-key`);
  }

  
  createCredential(data: CreateCredentialRequestDto): Observable<void> {
    return this.http.post<void>(`${this.baseUrl}/credentials`, data);
  }

  getEncryptedPassword(id: number): Observable<EncryptedPasswordResponseDto> {
    return this.http.get<EncryptedPasswordResponseDto>(`${this.baseUrl}/credentials/${id}/password`);
  }

  getPublicKeyByEmail(email: string): Observable<UserPublicKeyDto> {
    return this.http.get<UserPublicKeyDto>(`${this.baseUrl}/user/email/${email}/public-key`);
  }

  shareCredential(id: number, data: ShareCredentialRequestDto): Observable<void> {
    return this.http.post<void>(`${this.baseUrl}/credentials/${id}/share`, data);
  }
}