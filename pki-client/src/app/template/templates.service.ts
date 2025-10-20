import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable } from 'rxjs';
import { Template, TemplateCreate } from './template.model';
import { environment } from '../environment';

@Injectable({
  providedIn: 'root'
})
export class TemplateService {
  private apiUrl = environment.apiUrl + '/api/templates';

  constructor(private http: HttpClient) { }

  getTemplates(): Observable<Template[]> {
    return this.http.get<Template[]>(this.apiUrl);
  }

  createTemplate(templateData: TemplateCreate): Observable<Template> {
    return this.http.post<Template>(this.apiUrl, templateData);
  }

  deleteTemplate(id: number): Observable<void> {
    return this.http.delete<void>(`${this.apiUrl}/${id}`);
  }
}