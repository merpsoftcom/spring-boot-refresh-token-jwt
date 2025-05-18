package com.bezkoder.spring.security.jwt.models;

import com.fasterxml.jackson.annotation.JsonIgnore;
import jakarta.persistence.*;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Entity
@Table(	name = "users",
		uniqueConstraints = {
			@UniqueConstraint(columnNames = "username"),
			@UniqueConstraint(columnNames = "email")
		})
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class User {
	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	private Long id;

	@NotBlank
	@Size(max = 20)
    @Column(updatable = false)
    private String username;

	@NotBlank
	@Size(max = 50)
	@Email
    @Column(updatable = false)
    private String email;

    private boolean isDisabled;

    @JsonIgnore
    private boolean isInternal;

    private boolean isMFAEnabled;

    private boolean isMFAEnrolled;

    @JsonIgnore
    private String MFASecretKey;

    @NotBlank
	@Size(max = 120)
    @JsonIgnore
	private String password;

    @NotNull
    @ManyToOne
    Role role;
}
