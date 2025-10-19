package rs.ac.uns.ftn.bsep.pki_service.controller;

import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;
import rs.ac.uns.ftn.bsep.pki_service.dto.TemplateCreateDto;
import rs.ac.uns.ftn.bsep.pki_service.dto.TemplateResponseDto;
import rs.ac.uns.ftn.bsep.pki_service.model.Template;
import rs.ac.uns.ftn.bsep.pki_service.service.TemplateService;

import java.util.List;

@RestController
@RequestMapping("/api/templates")
@RequiredArgsConstructor
public class TemplateController {

    private final TemplateService templateService;

    @PostMapping
    @PreAuthorize("hasRole('CA_USER')")
    public ResponseEntity<Template> createTemplate(@RequestBody TemplateCreateDto dto) {
        Template newTemplate = templateService.createTemplate(dto);
        return new ResponseEntity<>(newTemplate, HttpStatus.CREATED);
    }

    @GetMapping
    @PreAuthorize("hasRole('CA_USER')")
    public ResponseEntity<List<TemplateResponseDto>> getUserTemplates() {
        return ResponseEntity.ok(templateService.getTemplatesForCurrentUser());
    }

    @DeleteMapping("/{id}")
    @PreAuthorize("hasRole('CA_USER')")
    public ResponseEntity<Void> deleteTemplate(@PathVariable Long id) {
        templateService.deleteTemplate(id);
        return ResponseEntity.noContent().build();
    }
}
