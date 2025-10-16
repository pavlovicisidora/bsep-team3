import { ComponentFixture, TestBed } from '@angular/core/testing';

import { ForcePasswordChangeComponent } from './force-password-change.component';

describe('ForcePasswordChangeComponent', () => {
  let component: ForcePasswordChangeComponent;
  let fixture: ComponentFixture<ForcePasswordChangeComponent>;

  beforeEach(() => {
    TestBed.configureTestingModule({
      declarations: [ForcePasswordChangeComponent]
    });
    fixture = TestBed.createComponent(ForcePasswordChangeComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
