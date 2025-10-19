import { ComponentFixture, TestBed } from '@angular/core/testing';

import { CertificateHistoryComponent } from './certificate-history.component';

describe('CertificateHistoryComponent', () => {
  let component: CertificateHistoryComponent;
  let fixture: ComponentFixture<CertificateHistoryComponent>;

  beforeEach(() => {
    TestBed.configureTestingModule({
      declarations: [CertificateHistoryComponent]
    });
    fixture = TestBed.createComponent(CertificateHistoryComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
