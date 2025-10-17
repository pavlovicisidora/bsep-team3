import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable } from 'rxjs';


export interface CreateRootCertificateDto {
  commonName: string;
  organization: string;
  organizationalUnit: string;
  country: string;
  email: string;
  validFrom: string;
  validTo: string;
  ownerId: number;
}

export interface CreateIntermediateCertificateDto {
  issuerSerialNumber: string;
  commonName: string;
  organization: string;
  organizationalUnit: string;
  country: string;
  email: string;
  validFrom: string;
  validTo: string;
  ownerId: number;
}

export interface Issuer {
  serialNumber: string;
  commonName: string;
  validTo: string;
}

export interface CertificateData {
  id: number;
  serialNumber: string;
  subjectDN: string;
  issuerDN: string;
  validFrom: string;
  validTo: string;
  ca: boolean;
  alias: string;
}


export interface CaUser {
  id: number;
  firstName: string;
  lastName: string;
  email: string;
}

export interface CertificateDetailsDto {
  serialNumber: string;
  commonName: string;
  issuerCommonName: string;
  validFrom: string;
  validTo: string;
  isCa: boolean;
  isRevoked: boolean;
  ownerUsername: string;
  alias: string;
}

@Injectable({
  providedIn: 'root'
})
export class CertificateManagementService {

  
  private readonly certApiUrl = 'http://localhost:8080/api/certificates';
  private readonly userApiUrl = 'http://localhost:8080/api/user';
  private readonly requestApiUrl = 'http://localhost:8080/api/certificate-requests';

  constructor(private http: HttpClient) { }

  // --- METODE ZA SERTIFIKATE ---

  createRootCertificate(certificateDto: CreateRootCertificateDto): Observable<CertificateData> {
    const endpoint = `${this.certApiUrl}/root`;
    return this.http.post<CertificateData>(endpoint, certificateDto);
  }

  getIssuers(): Observable<Issuer[]> {
    const endpoint = `${this.certApiUrl}/issuers`;
    return this.http.get<Issuer[]>(endpoint);
  }

  createIntermediateCertificate(certificateDto: CreateIntermediateCertificateDto): Observable<CertificateData> {
    const endpoint = `${this.certApiUrl}/intermediate`;
    return this.http.post<CertificateData>(endpoint, certificateDto);
  }

  createCertificateRequest(issuerSerialNumber: string, validTo: string, csrFile: File): Observable<any> {
    
    const formData = new FormData();

    
    formData.append('csrFile', csrFile, csrFile.name);
    formData.append('issuerSerialNumber', issuerSerialNumber);
    formData.append('validTo', validTo);

    return this.http.post(this.requestApiUrl, formData);
  }

  // --- METODA ZA CA KORISNIKE ---


  getAllCaUsers(): Observable<CaUser[]> {
    const endpoint = `${this.userApiUrl}/ca-users`; 
    return this.http.get<CaUser[]>(endpoint);
  }

  getAllCertificates(): Observable<CertificateDetailsDto[]> {
    return this.http.get<CertificateDetailsDto[]>(this.certApiUrl);
  }
}