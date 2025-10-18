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
  organization: string;
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
  ca: boolean;
  revoked: boolean;
  revocationReason: string | null;
  ownerUsername: string;
  alias: string;
}

export interface Requester {
  id: number;
  email: string;
  firstName: string;
  lastName: string;
  username: string;
  // ... i ostala polja ako su potrebna
}

// Glavni interfejs koji se poklapa sa JSON odgovorom
export interface CertificateRequestResponse {
  id: number;
  requester: Requester; // Ugnježdeni objekat
  createdAt: string;
  issuerSerialNumber: string;
  requestedValidTo: string;
  csrPem: string; // Sirovi PEM string
  status: 'PENDING' | 'APPROVED' | 'REJECTED';
  rejectionReason: string | null;
}

// Interfejs za parsirane CSR podatke koje ćemo mi kreirati na frontendu
export interface CsrDetails {
  commonName: string;
  organization: string;
  organizationalUnit: string;
  country: string;
  email: string;
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

    // 1. Kreiramo DTO objekat koji backend očekuje.
    const dto = {
      issuerSerialNumber: issuerSerialNumber,
      validTo: validTo
    };

    // 2. Pretvaramo DTO objekat u JSON string i umotavamo ga u Blob.
    // Ovo je ključno da bi Spring Boot ispravno pročitao 'dto' deo.
    const dtoBlob = new Blob([JSON.stringify(dto)], { type: 'application/json' });

    // 3. Dodajemo oba dela u FormData sa ispravnim imenima.
    formData.append('dto', dtoBlob);
    formData.append('csrFile', csrFile, csrFile.name);

    // 4. Proveravamo da li je endpoint ispravan. Na osnovu tvog backend koda,
    // on se nalazi u CertificateController-u i putanja je /end-entity.
    const endpoint = `${this.requestApiUrl}`;

    // Angular će automatski postaviti ispravan Content-Type za multipart/form-data.
    return this.http.post(endpoint, formData);
}



 getPendingRequests(): Observable<CertificateRequestResponse[]> {
    return this.http.get<CertificateRequestResponse[]>(`${this.requestApiUrl}/pending`);
  }

  
  approveRequest(requestId: number): Observable<any> {
    return this.http.post(`${this.requestApiUrl}/${requestId}/approve`, {});
  }

 
  rejectRequest(requestId: number, reason: string): Observable<void> {
    return this.http.post<void>(`${this.requestApiUrl}/${requestId}/reject`, { reason });
  }


  getMyRequests(): Observable<CertificateRequestResponse[]> {
    return this.http.get<CertificateRequestResponse[]>(`${this.requestApiUrl}/my-requests`);
  }



  // --- METODA ZA CA KORISNIKE ---


  getAllCaUsers(): Observable<CaUser[]> {
    const endpoint = `${this.userApiUrl}/ca-users`; 
    return this.http.get<CaUser[]>(endpoint);
  }

  getAllCertificates(): Observable<CertificateDetailsDto[]> {
    return this.http.get<CertificateDetailsDto[]>(this.certApiUrl);
  }

  revokeCertificate(serialNumber: string, reason: string): Observable<any> {
    const body = { reason: reason };
    return this.http.post(`${this.certApiUrl}/${serialNumber}/revoke`, body, { responseType: 'text' });
  }

  // Metoda za preuzimanje CRL-a
  downloadCrl(issuerAlias: string): Observable<Blob> {
    return this.http.get(`${this.certApiUrl}/crl/${issuerAlias}`, {
      responseType: 'blob'
    });
  }
}