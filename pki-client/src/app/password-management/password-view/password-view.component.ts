// src/app/components/password-view/password-view.component.ts
import { Component, OnInit } from '@angular/core';
import { FormBuilder, FormGroup, Validators } from '@angular/forms';
import { Observable, of } from 'rxjs';
import { catchError, first } from 'rxjs/operators';

import { PasswordManagementService,  CredentialResponseDto} from '../password-management.service'; 
import { CryptoService } from './crypto.service';
import { ShareCredentialRequestDto } from '../password-management.service';

@Component({
  selector: 'app-password-view',
  templateUrl: './password-view.component.html',
  styleUrls: ['./password-view.component.css']
})
export class PasswordViewComponent implements OnInit {

  // --- Stanje za prikaz tabele ---
  credentials$!: Observable<CredentialResponseDto[]>;
  errorMsg: string | null = null;
  
  // --- Stanje za formu za dodavanje ---
  showAddForm = false;
  addForm!: FormGroup;
  isSubmitting = false;
  formError: string | null = null;

  // === Stanje za modal za pregled ===
  isViewing = false; // Da li je modal otvoren
  isDecrypting = false; // Da li je proces dešifrovanja u toku (za spinner)
  selectedCredentialForView: CredentialResponseDto | null = null; // Koji nalog gledamo
  decryptedPassword: string | null = null; // Ovde će biti dešifrovana lozinka
  viewingError: string | null = null; // Greška pri dešifrovanju


  // --- Stanje za modal za deljenje ---
  isSharing = false;
  selectedCredentialForShare: CredentialResponseDto | null = null;
  sharingForm!: FormGroup;
  sharingError: string | null = null;
  isShareSubmitting = false;

  constructor(
    private passwordService: PasswordManagementService,
    private cryptoService: CryptoService,
    private fb: FormBuilder
  ) { }

  ngOnInit(): void {
    this.loadCredentials();
    this.addForm = this.fb.group({
      siteName: ['', Validators.required],
      username: ['', Validators.required],
      password: ['', Validators.required]
    });

     this.sharingForm = this.fb.group({
      email: ['', [Validators.required, Validators.email]]
    });
  }

  // --- Metode za listu i formu ---

  loadCredentials(): void {
    this.errorMsg = null;
    this.credentials$ = this.passwordService.getCredentials().pipe(
      catchError(err => {
        this.errorMsg = 'Došlo je do greške prilikom učitavanja podataka.';
        console.error(err);
        return of([]);
      })
    );
  }
  
  onAddNew(): void {
    this.showAddForm = true;
    this.formError = null;
    this.addForm.reset();
  }
  
  onCancelAdd(): void {
    this.showAddForm = false;
  }
  
  async onSubmit(): Promise<void> {
    if (this.addForm.invalid) return;
    this.isSubmitting = true;
    this.formError = null;
    try {
      const publicKeyData = await this.passwordService.getCurrentUserPublicKey().pipe(first()).toPromise();
      if (!publicKeyData || !publicKeyData.publicKey) throw new Error('Javni ključ korisnika nije pronađen.');
      
      const publicKey = await this.cryptoService.importPublicKey(publicKeyData.publicKey);
      const originalPassword = this.addForm.value.password;
      const encryptedPassword = await this.cryptoService.encryptPassword(originalPassword, publicKey);
      
      const requestData = {
        siteName: this.addForm.value.siteName,
        username: this.addForm.value.username,
        encryptedPassword: encryptedPassword
      };
      
      await this.passwordService.createCredential(requestData).pipe(first()).toPromise();
      this.showAddForm = false;
      this.loadCredentials();
    } catch (err) {
      console.error(err);
      this.formError = 'Došlo je do greške prilikom čuvanja.';
    } finally {
      this.isSubmitting = false;
    }
  }


  onView(credential: CredentialResponseDto): void {
    this.isViewing = true;
    this.selectedCredentialForView = credential;
    this.decryptedPassword = null;
    this.viewingError = null;
  }

  onCloseViewModal(): void {
    this.isViewing = false;
    this.selectedCredentialForView = null;
  }
  
  async onPrivateKeySelect(event: Event): Promise<void> {
    const input = event.target as HTMLInputElement;
    if (!input.files || input.files.length === 0) return;
    const file = input.files[0];

    this.isDecrypting = true;
    this.decryptedPassword = null;
    this.viewingError = null;

    try {
      const privateKeyPem = await this.readFileAsText(file);
      const privateKey = await this.cryptoService.importPrivateKey(privateKeyPem);
      
      
      const response = await this.passwordService.getEncryptedPassword(this.selectedCredentialForView!.id).pipe(first()).toPromise();
      const encryptedPasswordBase64 = response!.encryptedPassword;

      const decrypted = await this.cryptoService.decryptPassword(encryptedPasswordBase64, privateKey);
      this.decryptedPassword = decrypted;

    } catch (err) {
      console.error(err);
      this.viewingError = 'Greška pri dešifrovanju. Proverite da li ste odabrali ispravan privatni ključ.';
    } finally {
      this.isDecrypting = false;
      input.value = ''; 
    }
  }

  private readFileAsText(file: File): Promise<string> {
    return new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.onload = () => resolve(reader.result as string);
      reader.onerror = () => reject(reader.error);
      reader.readAsText(file);
    });
  }


   onShare(credential: CredentialResponseDto): void {
    this.isSharing = true;
    this.selectedCredentialForShare = credential;
    this.sharingForm.reset();
    this.sharingError = null;
    this.isShareSubmitting = false;
  }

  onCloseShareModal(): void {
    this.isSharing = false;
  }

  async onShareSubmit(privateKeyFile: File | null): Promise<void> {
    if (this.sharingForm.invalid) {
      this.sharingForm.markAllAsTouched();
      return;
    }
    if (!privateKeyFile) {
      this.sharingError = 'Morate odabrati svoj privatni ključ da biste potvrdili akciju.';
      return;
    }
    this.isShareSubmitting = true;
    this.sharingError = null;
    const targetEmail = this.sharingForm.value.email;

    try {
      // 1. Dešifruj lozinku svojim privatnim ključem
      const privateKeyPem = await this.readFileAsText(privateKeyFile);
      const privateKey = await this.cryptoService.importPrivateKey(privateKeyPem);
      const passResponse = await this.passwordService.getEncryptedPassword(this.selectedCredentialForShare!.id).pipe(first()).toPromise();
      if (!passResponse) throw new Error('Nije dobijena šifrovana lozinka sa servera.');
      const originalPassword = await this.cryptoService.decryptPassword(passResponse.encryptedPassword, privateKey);

      // 2. Dobavi javni ključ korisnika kome se deli
      const targetUserKeyData = await this.passwordService.getPublicKeyByEmail(targetEmail).pipe(first()).toPromise();
      if (!targetUserKeyData?.publicKey) throw new Error('Javni ključ za uneti email nije pronađen.');
      
      // 3. Šifruj originalnu lozinku njegovim javnim ključem
      const targetPublicKey = await this.cryptoService.importPublicKey(targetUserKeyData.publicKey);
      const encryptedPasswordForTarget = await this.cryptoService.encryptPassword(originalPassword, targetPublicKey);

      // 4. Pripremi i pošalji podatke na server
      const shareRequest: ShareCredentialRequestDto = {
        shareWithUserEmail: targetEmail,
        encryptedPasswordForUser: encryptedPasswordForTarget
      };
      await this.passwordService.shareCredential(this.selectedCredentialForShare!.id, shareRequest).pipe(first()).toPromise();

      this.isSharing = false; // Uspeh! Zatvori modal.

    } catch (err: any) {
      console.error(err);
      this.sharingError = err.error?.message || 'Došlo je do greške. Proverite email i da li ste odabrali ispravan ključ.';
    } finally {
      this.isShareSubmitting = false;
    }
  }
}