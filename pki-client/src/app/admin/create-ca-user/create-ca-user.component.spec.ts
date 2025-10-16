import { ComponentFixture, TestBed } from '@angular/core/testing';

import { CreateCaUserComponent } from './create-ca-user.component';

describe('CreateCaUserComponent', () => {
  let component: CreateCaUserComponent;
  let fixture: ComponentFixture<CreateCaUserComponent>;

  beforeEach(() => {
    TestBed.configureTestingModule({
      declarations: [CreateCaUserComponent]
    });
    fixture = TestBed.createComponent(CreateCaUserComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
