package com.bezkoder.spring.security.jwt.configuration;

import com.bezkoder.spring.security.jwt.models.Permission;
import com.bezkoder.spring.security.jwt.models.Role;
import com.bezkoder.spring.security.jwt.models.User;
import com.bezkoder.spring.security.jwt.repository.RoleRepository;
import com.bezkoder.spring.security.jwt.repository.UserRepository;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.util.*;

@Component
public class DefaultValuesInitializer implements CommandLineRunner {

    public static final String SUPER_ROLE = "SuperRole";
    public static final String SUPER_USER = "SuperUser";
    @Value("${super.user.password:SuperPassword@123}")
    public String SUPER_PASSWORD;
    private final RoleRepository roleRepository;
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    public DefaultValuesInitializer( RoleRepository roleRepository, UserRepository userRepository, PasswordEncoder passwordEncoder) {
        this.roleRepository = roleRepository;
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }


    @Override
    public void run(String... args) {
        createDefaultRoles();
        createSuperUser();
    }

    private void createDefaultRoles() {
        if (roleRepository.findByName(SUPER_ROLE).isEmpty())
            roleRepository.save(Role.builder()
                .name(SUPER_ROLE)
                .permissions(new HashSet<>(List.of(Permission.values())))
                .isInternal(true)
                .build());
    }

    private void createSuperUser() {
        if (userRepository.findByUsername(SUPER_USER).isEmpty())
            userRepository.save(User.builder()
                .username(SUPER_USER)
                .isInternal(true)
                .email("superuser@gmail.com")
                .password(passwordEncoder.encode(SUPER_PASSWORD))
                .role(roleRepository.findByName(SUPER_ROLE)
                    .orElseThrow(() -> new RuntimeException("Super User creation failed due to unavailable SuperRole in DB")))
            .build());
    }

}
