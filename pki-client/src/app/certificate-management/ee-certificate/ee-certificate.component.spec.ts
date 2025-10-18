import { ComponentFixture, TestBed } from '@angular/core/testing';

import { EeCertificateComponent } from './ee-certificate.component';

describe('EeCertificateComponent', () => {
  let component: EeCertificateComponent;
  let fixture: ComponentFixture<EeCertificateComponent>;

  beforeEach(() => {
    TestBed.configureTestingModule({
      declarations: [EeCertificateComponent]
    });
    fixture = TestBed.createComponent(EeCertificateComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
