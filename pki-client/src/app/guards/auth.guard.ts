import { Injectable } from '@angular/core';
import { CanActivate, ActivatedRouteSnapshot, RouterStateSnapshot, UrlTree, Router } from '@angular/router';
import { map, Observable, take } from 'rxjs';
import { AuthService } from '../auth/auth.service';

@Injectable({
  providedIn: 'root'
})
export class AuthGuard implements CanActivate {

  constructor(private authService: AuthService, private router: Router) {}

  canActivate(route: ActivatedRouteSnapshot): boolean | UrlTree {
    
    if (!this.authService.isLoggedIn()) {
      return this.router.createUrlTree(['/login']);
    }

    const expectedRoles = route.data['expectedRoles'] as Array<string>;
    if (!expectedRoles) {
      return true; 
    }

    const user = this.authService.currentUserValue;
    if (user && expectedRoles.includes(user.role)) {
      return true; 
    }

    console.warn(`Access denied. User with role ${user?.role} tried to access a route requiring roles: ${expectedRoles}`);
    return this.router.createUrlTree(['/dashboard']);
  }
}
