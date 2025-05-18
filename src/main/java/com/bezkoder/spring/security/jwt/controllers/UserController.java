package com.bezkoder.spring.security.jwt.controllers;

import com.bezkoder.spring.security.jwt.models.Permission;
import com.bezkoder.spring.security.jwt.models.Role;
import com.bezkoder.spring.security.jwt.models.User;
import com.bezkoder.spring.security.jwt.payload.request.RoleRequest;
import com.bezkoder.spring.security.jwt.repository.RoleRepository;
import com.bezkoder.spring.security.jwt.repository.UserRepository;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
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
public class UserController {
    @Autowired
    UserRepository userRepository;


//    @PostMapping("/users")
//    @PreAuthorize("hasRole('CREATE_USERS')")
//    public ResponseEntity<Role> createRole(@Valid @RequestBody RoleRequest roleRequest) throws URISyntaxException {
//        User role = userRepository.save(User.builder()
//            .username(roleRequest.getName())
//            .email(roleRequest.getDescription())
//            .permissions(roleRequest.getPermissions().stream()
//                .map(Permission::valueOf)
//                .collect(Collectors.toSet()))
//            .build());
//        return ResponseEntity.created(new URI("/users/" + role.getId())).body(role);
//    }
//    @PostMapping("/users/{id}")
//    @PreAuthorize("hasRole('UPDATE_USERS')")
//    public ResponseEntity<?> updateRole(@Valid @PathVariable(name = "id") long id
//        , @Valid @RequestBody RoleRequest roleRequest) {
//        Optional<User> role = userRepository.findById(id);
//        role.ifPresentOrElse(
//            role1 -> {
//                if (role1.isInternal()) {
//                    throw new RuntimeException("Can't update internal role");
//                } else {
//                    role1.setPermissions((roleRequest.getPermissions().stream()
//                        .map(Permission::valueOf)
//                        .collect(Collectors.toSet())));
//                    role1.setDescription(roleRequest.getDescription());
//                    userRepository.save(role1);
//                }
//            },
//            () -> { throw new RuntimeException("Role not found"); }
//        );
//        return ResponseEntity.ok("Role updated successfully");
//    }
//

    @GetMapping("/users/{id}")
    @PreAuthorize("hasRole('VIEW_USERS')")
    public ResponseEntity<User> getRoleById(@Valid @PathVariable(name = "id") long id) {
        return ResponseEntity.ok(userRepository.findById(id).get());
    }

    @DeleteMapping("/users/{id}")
    @PreAuthorize("hasRole('DELETE_USERS')")
    public ResponseEntity<?> deleteRoleById(@Valid @PathVariable(name = "id") long id) {
        Optional<User> role = userRepository.findById(id);
        role.ifPresentOrElse(
            role1 -> {
                if (role1.isInternal()) {
                    throw new RuntimeException("Can't delete internal role");
                } else {
                    userRepository.deleteById(id);
                }
            },
            () -> { throw new RuntimeException("Role not found"); }
        );
        return ResponseEntity.ok("Role deleted successfully");
    }

    @PreAuthorize("hasRole('VIEW_USERS')")
    @GetMapping("/users")
    public ResponseEntity<?> getUsers() {
        return ResponseEntity.ok().body(userRepository.findAll());
    }


}
