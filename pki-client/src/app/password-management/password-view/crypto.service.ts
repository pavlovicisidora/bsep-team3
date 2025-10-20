import { Injectable } from '@angular/core';

@Injectable({
  providedIn: 'root'
})
export class CryptoService {

  constructor() { }

  // Funkcija za konvertovanje PEM stringa (koji dobijamo sa backenda ili iz fajla)
  // u ArrayBuffer koji Web Crypto API može da koristi.
  private pemToArrayBuffer(pem: string): ArrayBuffer {
    // 1. Ukloni zaglavlje ("-----BEGIN..."), podnožje ("-----END...") i nove redove.
    const base64String = pem
      .replace(/-----BEGIN (PUBLIC|PRIVATE) KEY-----/, '')
      .replace(/-----END (PUBLIC|PRIVATE) KEY-----/, '')
      .replace(/\s/g, '');

    // 2. Dekodiraj Base64 string u binarni format.
    const binaryString = window.atob(base64String);
    const len = binaryString.length;
    const bytes = new Uint8Array(len);
    for (let i = 0; i < len; i++) {
      bytes[i] = binaryString.charCodeAt(i);
    }
    return bytes.buffer;
  }

  /**
   * Uvozi JAVNI ključ (u PEM formatu) i priprema ga za enkripciju.
   * @param pemKey Javni ključ kao string u PEM formatu.
   * @returns CryptoKey objekat spreman za enkripciju.
   */
  public async importPublicKey(pemKey: string): Promise<CryptoKey> {
    const arrayBuffer = this.pemToArrayBuffer(pemKey);
    return await window.crypto.subtle.importKey(
      'spki', // Standardni format za javne ključeve
      arrayBuffer,
      {
        name: 'RSA-OAEP',
        hash: 'SHA-256', // Mora da se poklapa sa onim što se koristi za enkripciju
      },
      true,
      ['encrypt'] // Kažemo da ovaj ključ može da se koristi za enkripciju
    );
  }

  /**
   * Uvozi PRIVATNI ključ (u PEM formatu) i priprema ga za dekripciju.
   * @param pemKey Privatni ključ kao string u PEM formatu.
   * @returns CryptoKey objekat spreman za dekripciju.
   */
  public async importPrivateKey(pemKey: string): Promise<CryptoKey> {
    const arrayBuffer = this.pemToArrayBuffer(pemKey);
    return await window.crypto.subtle.importKey(
      'pkcs8', // Standardni format za privatne ključeve
      arrayBuffer,
      {
        name: 'RSA-OAEP',
        hash: 'SHA-256',
      },
      true,
      ['decrypt'] // Kažemo da ovaj ključ može da se koristi za dekripciju
    );
  }

  /**
   * Glavna funkcija za ENKRIPCIJU lozinke.
   * @param password Originalna lozinka kao string.
   * @param publicKey CryptoKey objekat (javni ključ).
   * @returns Base64 enkodirana šifrovana lozinka.
   */
  public async encryptPassword(password: string, publicKey: CryptoKey): Promise<string> {
    const encodedPassword = new TextEncoder().encode(password);
    const encryptedBuffer = await window.crypto.subtle.encrypt(
      { name: 'RSA-OAEP' },
      publicKey,
      encodedPassword
    );
    // Pretvaranje ArrayBuffer u Base64 string
    const base64String = btoa(String.fromCharCode(...new Uint8Array(encryptedBuffer)));
    return base64String;
  }

  /**
   * Glavna funkcija za DEKRIPCIJU lozinke.
   * @param encryptedBase64 Šifrovana lozinka (Base64 string).
   * @param privateKey CryptoKey objekat (privatni ključ).
   * @returns Originalna, dešifrovana lozinka.
   */
  public async decryptPassword(encryptedBase64: string, privateKey: CryptoKey): Promise<string> {
    // Pretvaranje Base64 stringa u ArrayBuffer
    const binaryString = atob(encryptedBase64);
    const len = binaryString.length;
    const bytes = new Uint8Array(len);
    for (let i = 0; i < len; i++) {
      bytes[i] = binaryString.charCodeAt(i);
    }
    const encryptedBuffer = bytes.buffer;

    const decryptedBuffer = await window.crypto.subtle.decrypt(
      { name: 'RSA-OAEP' },
      privateKey,
      encryptedBuffer
    );
    return new TextDecoder().decode(decryptedBuffer);
  }
}