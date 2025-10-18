import { ComponentFixture, TestBed } from '@angular/core/testing';

import { RevokeDialogComponent } from './revoke-dialog.component';

describe('RevokeDialogComponent', () => {
  let component: RevokeDialogComponent;
  let fixture: ComponentFixture<RevokeDialogComponent>;

  beforeEach(() => {
    TestBed.configureTestingModule({
      declarations: [RevokeDialogComponent]
    });
    fixture = TestBed.createComponent(RevokeDialogComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
