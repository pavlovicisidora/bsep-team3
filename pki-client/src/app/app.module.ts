import { NgModule } from '@angular/core';
import { BrowserModule } from '@angular/platform-browser';
import { ReactiveFormsModule } from '@angular/forms';
import { BrowserAnimationsModule } from '@angular/platform-browser/animations';

import { MatSnackBarModule } from '@angular/material/snack-bar';
import { MatDialogModule } from '@angular/material/dialog';
import { MatCardModule } from '@angular/material/card';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatInputModule } from '@angular/material/input';
import { MatButtonModule } from '@angular/material/button';
import { MatProgressSpinnerModule } from '@angular/material/progress-spinner';
import { FormsModule } from '@angular/forms';

import { AppRoutingModule } from './app-routing.module';
import { AppComponent } from './app.component';
import { RegisterComponent } from './auth/register/register.component';

import { HTTP_INTERCEPTORS, HttpClientModule } from '@angular/common/http';
import { AuthInterceptor } from './interceptors/auth.interceptor';
import { LoginComponent } from './auth/login/login.component';
import { NgxCaptchaModule } from 'ngx-captcha';
import { DashboardComponent } from './dashboard/dashboard.component';
import { MatToolbarModule } from '@angular/material/toolbar'; 
import { MatIconModule } from '@angular/material/icon';
import { MatSelectModule } from '@angular/material/select';
import { MatTooltipModule } from '@angular/material/tooltip';

import { ForgotPasswordDialogComponent } from './auth/forgot-password-dialog/forgot-password-dialog.component';
import { ResetPasswordComponent } from './auth/reset-password/reset-password.component';

import { ForcePasswordChangeComponent } from './auth/force-password-change/force-password-change.component';
import { NavbarComponent } from './navbar/navbar.component';
import { CreateCaUserComponent } from './admin/create-ca-user/create-ca-user.component';
import { ActiveSessionComponent } from './session-management/active-session/active-session.component';
import { RootCertificateComponent } from './certificate-management/root-certificate/root-certificate.component';
import { IntermediateCertificateComponent } from './certificate-management/intermediate-certificate/intermediate-certificate.component';
import { EeCertificateComponent } from './certificate-management/ee-certificate/ee-certificate.component';
import { CertificateViewComponent } from './certificate-management/certificate-view/certificate-view.component';
import { RevokeDialogComponent } from './certificate-management/revoke-dialog/revoke-dialog.component';
import { TemplateFormComponent } from './template/template-form/template-form.component';
import { TemplateListComponent } from './template/template-list/template-list.component';
import { CertificateRequestsComponent } from './certificate-management/certificate-requests/certificate-requests.component';
import { CertificateHistoryComponent } from './certificate-management/certificate-history/certificate-history.component';
import { PasswordViewComponent } from './password-management/password-view/password-view.component';



@NgModule({
  declarations: [
    AppComponent,
    RegisterComponent,
    LoginComponent,
    DashboardComponent,
    ForgotPasswordDialogComponent,
    ResetPasswordComponent,
    ForcePasswordChangeComponent,
    NavbarComponent,
    CreateCaUserComponent,
    ActiveSessionComponent,
    RootCertificateComponent,
    IntermediateCertificateComponent,
    EeCertificateComponent,
    CertificateViewComponent,
    RevokeDialogComponent,
    TemplateFormComponent,
    TemplateListComponent,
    CertificateRequestsComponent,
    CertificateHistoryComponent,
    PasswordViewComponent
  ],
  imports: [
    BrowserModule,
    AppRoutingModule,
    HttpClientModule,
    ReactiveFormsModule,
    BrowserAnimationsModule,
    NgxCaptchaModule,
    MatCardModule,
    MatFormFieldModule,
    MatInputModule,
    MatButtonModule,
    MatProgressSpinnerModule,
    MatToolbarModule,
    MatIconModule,
    HttpClientModule,
    FormsModule,
    MatDialogModule,
    MatSelectModule,
    MatSnackBarModule, 
    MatTooltipModule,
    HttpClientModule,

  ],
  providers: [
    {
      provide: HTTP_INTERCEPTORS,
      useClass: AuthInterceptor,
      multi: true
    }
  ],
  bootstrap: [AppComponent]
})
export class AppModule { }
