package com.bezkoder.spring.security.jwt.models;

import com.fasterxml.jackson.annotation.JsonIgnore;
import jakarta.persistence.*;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.HashSet;
import java.util.Set;

@Entity
@Table(	name = "roles", uniqueConstraints = {
    @UniqueConstraint(columnNames = "name")})
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class Role {
	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	private Long id;

	@NotBlank
	@Size(min = 6, max = 20)
    @Column(updatable = false)
    private String name;

    @Size(max = 40)
    private String description;

    @JsonIgnore
    private boolean isInternal;

    @ElementCollection
    @Enumerated(EnumType.STRING)
    private Set<Permission> permissions = new HashSet<>();
}
