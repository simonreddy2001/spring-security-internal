package no.noroff.statelessSecurity.controllers;

import no.noroff.statelessSecurity.models.domain.RoleType;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.annotation.security.RolesAllowed;

/*
    This is our controller where protected resources are accessible.
    We only want people who are authorized to access particular resources.
    We use @PreAuthorize to control which roles can access which resources.
 */

@CrossOrigin(origins = "*")
@RestController
@RequestMapping("/api/test")
public class TestController {
    // Endpoints
    @GetMapping("/all")
    public String allAccess() {
        return "Public Resources.";
    }

    @GetMapping("/user")
    //@PreAuthorize("hasRole('USER') or hasRole('MODERATOR') or hasRole('ADMIN')")
    @RolesAllowed({"USER","MODERATOR","ADMIN"})
    public String userAccess() {
        return "User Resources.";
    }

    @GetMapping("/mod")
    //@PreAuthorize("hasRole('MODERATOR')")
    @RolesAllowed("MODERATOR")
    public String moderatorAccess() {
        return "Moderator Resources.";
    }

    @GetMapping("/admin")
    @PreAuthorize("hasRole('ADMIN')")
    public String adminAccess() {
        return "Admin Resources.";
    }
}
