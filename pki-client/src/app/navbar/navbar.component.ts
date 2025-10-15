import { Component } from '@angular/core';
import { Observable } from 'rxjs';
import { map } from 'rxjs/operators';
import { AuthService } from '../auth/auth.service';

@Component({
  selector: 'app-navbar',
  templateUrl: './navbar.component.html',
  styleUrls: ['./navbar.component.css']
})
export class NavbarComponent {
  isLoggedIn$: Observable<boolean>;
  isAdmin$: Observable<boolean>;
  isCaUser$: Observable<boolean>;
  isOrdinaryUser$: Observable<boolean>;

  constructor(public authService: AuthService) {
    this.isLoggedIn$ = this.authService.currentUser$.pipe(map(user => !!user));
    this.isAdmin$ = this.authService.currentUser$.pipe(map(user => user && user.role === 'ADMIN'));
    this.isCaUser$ = this.authService.currentUser$.pipe(map(user => user && user.role === 'CA_USER'));
    this.isOrdinaryUser$ = this.authService.currentUser$.pipe(map(user => user && user.role === 'ORDINARY_USER'));
  }

  logout(): void {
    this.authService.logout();
  }
}