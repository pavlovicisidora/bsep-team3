import { TestBed } from '@angular/core/testing';

import { CertificateManagementService } from './certificate-management.service';

describe('CertificateManagementService', () => {
  let service: CertificateManagementService;

  beforeEach(() => {
    TestBed.configureTestingModule({});
    service = TestBed.inject(CertificateManagementService);
  });

  it('should be created', () => {
    expect(service).toBeTruthy();
  });
});
