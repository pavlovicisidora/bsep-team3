import { NgModule } from '@angular/core';
import { RouterModule, Routes } from '@angular/router';
import { RegisterComponent } from './auth/register/register.component';
import { LoginComponent } from './auth/login/login.component';
import { AuthGuard } from './guards/auth.guard';
import { DashboardComponent } from './dashboard/dashboard.component';
import { ForcePasswordChangeComponent } from './auth/force-password-change/force-password-change.component';
import { CreateCaUserComponent } from './admin/create-ca-user/create-ca-user.component';

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
    path: 'create-ca-user', 
    component: CreateCaUserComponent,
    canActivate: [AuthGuard],
    data: { expectedRoles: ['ADMIN'] }
  },
      
  { path: '', redirectTo: '/dashboard', pathMatch: 'full' },
  { path: '**', redirectTo: '/login' } 
];

@NgModule({
  imports: [RouterModule.forRoot(routes)],
  exports: [RouterModule]
})
export class AppRoutingModule { }
