import { ComponentFixture, TestBed } from '@angular/core/testing';

import { RootCertificateComponent } from './root-certificate.component';

describe('RootCertificateComponent', () => {
  let component: RootCertificateComponent;
  let fixture: ComponentFixture<RootCertificateComponent>;

  beforeEach(() => {
    TestBed.configureTestingModule({
      declarations: [RootCertificateComponent]
    });
    fixture = TestBed.createComponent(RootCertificateComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
