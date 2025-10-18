import { NgModule } from '@angular/core';
import { RouterModule, Routes } from '@angular/router';
import { RegisterComponent } from './auth/register/register.component';
import { LoginComponent } from './auth/login/login.component';
import { AuthGuard } from './guards/auth.guard';
import { DashboardComponent } from './dashboard/dashboard.component';
import { ResetPasswordComponent } from './auth/reset-password/reset-password.component';
import { ForcePasswordChangeComponent } from './auth/force-password-change/force-password-change.component';
import { CreateCaUserComponent } from './admin/create-ca-user/create-ca-user.component';
import { ActiveSessionComponent } from './session-management/active-session/active-session.component';
import { RootCertificateComponent } from './certificate-management/root-certificate/root-certificate.component'; 
import { IntermediateCertificateComponent } from './certificate-management/intermediate-certificate/intermediate-certificate.component';
import { EeCertificateComponent } from './certificate-management/ee-certificate/ee-certificate.component';

const routes: Routes = [
  { path: 'login', component: LoginComponent },
  { path: 'register', component: RegisterComponent },
  { 
    path: 'force-password-change', 
    component: ForcePasswordChangeComponent,
    canActivate: [AuthGuard] 
  },
  { 
    path: 'dashboard', 
    component: DashboardComponent, 
    canActivate: [AuthGuard]
  },

  { 
    path: 'sessions', // URL će biti /sessions
    component: ActiveSessionComponent, 
    canActivate: [AuthGuard] // OBAVEZNO zaštitite rutu!
  },
  
  { path: '', redirectTo: '/login', pathMatch: 'full' },
  { path: 'reset-password', component: ResetPasswordComponent },
  { 
    path: 'create-ca-user', 
    component: CreateCaUserComponent,
    canActivate: [AuthGuard],
    data: { expectedRoles: ['ADMIN'] }
  },
   {
    path: 'create-root-certificate',
    component: RootCertificateComponent,
    canActivate: [AuthGuard],
    data: { expectedRoles: ['ADMIN'] } 
  },

  
  {
    path: 'create-intermediate-certificate',
    component: IntermediateCertificateComponent,
    canActivate: [AuthGuard],
    data: { expectedRoles: ['ADMIN', 'CA_USER'] } 
  },
  {
    path: 'certificate-request',
    component: EeCertificateComponent,
    canActivate: [AuthGuard],
    data: { expectedRoles: ['ORDINARY_USER'] } // Samo za obične korisnike
  },
      
  { path: '', redirectTo: '/dashboard', pathMatch: 'full' },
  { path: '**', redirectTo: '/login' } 
];

@NgModule({
  imports: [RouterModule.forRoot(routes)],
  exports: [RouterModule]
})
export class AppRoutingModule { }
