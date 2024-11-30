package com.example.signup.controller;

import com.example.signup.audit.AuditLog;
import com.example.signup.audit.AuditLogRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

import java.util.List;

@Controller
@RequestMapping("/audit")
public class AuditController {
    private final AuditLogRepository auditLogRepository;

    @Autowired
    public AuditController(AuditLogRepository auditLogRepository) {
        this.auditLogRepository = auditLogRepository;
    }

    @GetMapping("/logs")
    @PreAuthorize("hasRole('ADMIN')")  // Restrict access to admins
    public String viewAuditLogs(Model model) {
        List<AuditLog> auditLogs = auditLogRepository.findAll();
        model.addAttribute("auditLogs", auditLogs);
        return "audit_logs";  // This is the view where logs will be displayed
    }
}
