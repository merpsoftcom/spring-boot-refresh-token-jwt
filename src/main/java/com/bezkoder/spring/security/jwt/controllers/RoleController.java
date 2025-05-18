package com.bezkoder.spring.security.jwt.controllers;

import com.bezkoder.spring.security.jwt.exception.StandardException;
import com.bezkoder.spring.security.jwt.models.Permission;
import com.bezkoder.spring.security.jwt.models.Role;
import com.bezkoder.spring.security.jwt.payload.request.RoleRequest;
import com.bezkoder.spring.security.jwt.repository.RoleRepository;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Optional;
import java.util.stream.Collectors;

@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping("/api/auth")
public class RoleController {
    @Autowired
    RoleRepository roleRepository;


    @PostMapping("/roles")
    @PreAuthorize("hasRole('CREATE_ROLES')")
    public ResponseEntity<Role> createRole(@Valid @RequestBody RoleRequest roleRequest) throws URISyntaxException {
        Role role = roleRepository.save(Role.builder()
            .name(roleRequest.getName())
            .description(roleRequest.getDescription())
            .permissions(roleRequest.getPermissions().stream()
                .map(Permission::valueOf)
                .collect(Collectors.toSet()))
            .build());
        return ResponseEntity.created(new URI("/role/" + role.getId())).body(role);
    }
    @PostMapping("/roles/{id}")
    @PreAuthorize("hasRole('UPDATE_ROLES')")
    public ResponseEntity<?> updateRole(@Valid @PathVariable(name = "id") long id
        , @Valid @RequestBody RoleRequest roleRequest) {
        Role role = roleRepository.findById(id)
            .orElseThrow(() -> new StandardException(HttpStatus.NOT_FOUND, "Role not found"));

        if (role.isInternal()) {
            throw new StandardException(HttpStatus.NOT_ACCEPTABLE, "Can't update internal role");
        } else {
            role.setPermissions((roleRequest.getPermissions().stream()
                .map(Permission::valueOf)
                .collect(Collectors.toSet())));
            role.setDescription(roleRequest.getDescription());
            roleRepository.save(role);
        }

        return ResponseEntity.ok("Role updated successfully");
    }


    @GetMapping("/roles/{id}")
    @PreAuthorize("hasRole('VIEW_ROLES')")
    public ResponseEntity<Role> getRoleById(@Valid @PathVariable(name = "id") long id) {
        return ResponseEntity.ok(roleRepository.findById(id).get());
    }

    @DeleteMapping("/roles/{id}")
    @PreAuthorize("hasRole('DELETE_ROLES')")
    public ResponseEntity<?> deleteRoleById(@Valid @PathVariable(name = "id") long id) {
        Optional<Role> role = roleRepository.findById(id);
        role.ifPresentOrElse(
            role1 -> {
                if (role1.isInternal()) {
                    throw new RuntimeException("Can't delete internal role");
                } else {
                    roleRepository.deleteById(id);
                }
            },
            () -> { throw new RuntimeException("Role not found"); }
        );
        return ResponseEntity.ok("Role deleted successfully");
    }

    @GetMapping("/roles")
    @PreAuthorize("hasRole('VIEW_ROLES')")
    public ResponseEntity<?> getRoles() {
        return ResponseEntity.ok().body(roleRepository.findAll());
    }


}
