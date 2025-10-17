import { Component, OnInit } from '@angular/core';
import UAParser from 'ua-parser-js';
import { SessionManagementService } from '../session-managemen.service';
import { ActiveSession, ParsedSession } from '../model/model.session';

@Component({
  selector: 'app-active-session', // Ažuriran selector
  templateUrl: './active-session.component.html',
  styleUrls: ['./active-session.component.css']
})
export class ActiveSessionComponent implements OnInit {
  
  public sessions: ParsedSession[] = [];
  public isLoading = true;
  private currentSessionJti: string | null = null;

  constructor(private sessionService: SessionManagementService) { }

  ngOnInit(): void {
    this.getCurrentSessionJtiFromToken();
    this.loadActiveSessions();
  }

  loadActiveSessions(): void {
    this.isLoading = true;
    this.sessionService.getSessions().subscribe({
      next: (data) => {
        this.sessions = data.map(session => this.parseSessionForView(session));
        this.isLoading = false;
      },
      error: (err) => {
        console.error('Greška pri dohvatanju sesija:', err);
        this.isLoading = false;
      }
    });
  }

  revokeSession(jti: string): void {
    if (!confirm('Da li ste sigurni da želite da opozovete ovu sesiju?')) return;
    
    this.sessionService.revokeSession(jti).subscribe({
      next: () => {
        if (jti === this.currentSessionJti) {
          alert('Uspešno ste se odjavili sa ovog uređaja.');
          localStorage.removeItem('pki_auth_token');
          window.location.href = '/auth/login';
        } else {
          alert('Sesija je uspešno opozvana.');
          this.sessions = this.sessions.filter(s => s.jti !== jti);
        }
      },
      error: (err) => {
        console.error('Greška pri opozivanju sesije:', err);
        alert('Došlo je do greške.');
      }
    });
  }

  private getCurrentSessionJtiFromToken(): void {
    const token = localStorage.getItem('pki_auth_token');
    if (!token) return;
    try {
      const payload = JSON.parse(atob(token.split('.')[1]));
      this.currentSessionJti = payload.jti;
    } catch (e) { console.error('Greška pri dekodiranju tokena:', e); }
  }

  private parseSessionForView(session: ActiveSession): ParsedSession {
    const parser = new UAParser(session.userAgent);
    const result = parser.getResult();
    let deviceIcon = 'desktop_windows';
    const deviceType = result.device.type;
    if (deviceType === 'mobile') deviceIcon = 'smartphone';
    else if (deviceType === 'tablet') deviceIcon = 'tablet_mac';
    
    return {
      ...session,
      device: { icon: deviceIcon, name: result.os.name ? `${result.os.name} ${result.os.version}` : 'Nepoznat OS' },
      browser: { icon: 'public', name: result.browser.name || 'Nepoznat pretraživač' },
      isCurrentSession: session.jti === this.currentSessionJti
    };
  }

  formatDate(dateString: string): string {
    return new Date(dateString).toLocaleString('sr-RS');
  }

   public isSessionExpired(session: ParsedSession): boolean {
    return new Date(session.expiresAt) < new Date();
  }
}