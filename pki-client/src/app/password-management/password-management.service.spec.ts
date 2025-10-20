import { TestBed } from '@angular/core/testing';

import { PasswordManagementService } from './password-management.service';

describe('PasswordManagementService', () => {
  let service: PasswordManagementService;

  beforeEach(() => {
    TestBed.configureTestingModule({});
    service = TestBed.inject(PasswordManagementService);
  });

  it('should be created', () => {
    expect(service).toBeTruthy();
  });
});
