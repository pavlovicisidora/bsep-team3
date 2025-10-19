import { Component, OnInit } from '@angular/core';
import { Template } from '../template.model';
import { Observable } from 'rxjs';
import { TemplateService } from '../templates.service';

@Component({
  selector: 'app-template-list',
  templateUrl: './template-list.component.html',
  styleUrls: ['./template-list.component.css']
})
export class TemplateListComponent implements OnInit {
  templates: Template[] = [];

  constructor(private templateService: TemplateService) { }

  ngOnInit(): void {
    this.loadTemplates();
  }

  loadTemplates(): void {
    this.templateService.getTemplates().subscribe({
      next: (data) => this.templates = data,
      error: (err) => console.error('Failed to load templates', err)
    });
  }

  deleteTemplate(id: number): void {
    if (confirm('Are you sure you want to delete this template?')) {
      this.templateService.deleteTemplate(id).subscribe({
        next: () => {
          console.log('Template deleted successfully');
          this.loadTemplates(); 
        },
        error: (err) => console.error('Failed to delete template', err)
      });
    }
  }

  extractCn(dn: string): string {
    const match = dn.match(/CN=([^,]+)/);
    return match ? match[1] : 'N/A';
  }
}