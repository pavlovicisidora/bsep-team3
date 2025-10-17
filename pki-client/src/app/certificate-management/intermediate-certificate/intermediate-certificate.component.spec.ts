import { ComponentFixture, TestBed } from '@angular/core/testing';

import { IntermediateCertificateComponent } from './intermediate-certificate.component';

describe('IntermediateCertificateComponent', () => {
  let component: IntermediateCertificateComponent;
  let fixture: ComponentFixture<IntermediateCertificateComponent>;

  beforeEach(() => {
    TestBed.configureTestingModule({
      declarations: [IntermediateCertificateComponent]
    });
    fixture = TestBed.createComponent(IntermediateCertificateComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
