package com.bezkoder.spring.security.jwt.payload.request;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Getter;

import java.util.Set;

@Getter
public class RoleRequest {
    @NotBlank
    @Size(min = 3, max = 20)
    private String name;

    @Size(max = 40)
    private String description;

    Set<String> permissions;

}
