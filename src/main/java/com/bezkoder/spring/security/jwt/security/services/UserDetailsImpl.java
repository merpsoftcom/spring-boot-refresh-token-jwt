package com.bezkoder.spring.security.jwt.security.services;

import java.util.Collection;
import java.util.Objects;
import java.util.Set;

import com.bezkoder.spring.security.jwt.models.Permission;
import com.bezkoder.spring.security.jwt.models.User;
import lombok.Getter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;


public class UserDetailsImpl implements UserDetails {
	private static final long serialVersionUID = 1L;
    private final Collection<SimpleGrantedAuthority> authorities;

    @Getter
    private User user;
    public UserDetailsImpl(User user) {
        this.user = user;
        this.authorities = user.getRole().getPermissions().stream()
            .map(permission -> new SimpleGrantedAuthority(permission.name()))
            .toList();
    }

    public UserDetailsImpl(User user, Collection<String> permissions) {
        this.user = user;
        this.authorities = permissions.stream()
            .map(SimpleGrantedAuthority::new)
            .toList();
    }

    public Long getId() {
        return user.getId();
    }

    public String getEmail() {
        return user.getEmail();
    }

    public Set<Permission> getPermissions() {
        return user.getRole().getPermissions();
    }

    @Override
	public Collection<? extends GrantedAuthority> getAuthorities() {
		return authorities;
	}

    @Override
	public String getPassword() {
		return user.getPassword();
	}

	@Override
	public String getUsername() {
		return user.getUsername();
	}

	@Override
	public boolean isAccountNonExpired() {
		return true;
	}

	@Override
	public boolean isAccountNonLocked() {
		return true;
	}

	@Override
	public boolean isCredentialsNonExpired() {
		return true;
	}

	@Override
	public boolean isEnabled() {
		return !user.isDisabled();
	}

	@Override
	public boolean equals(Object o) {
		if (this == o)
			return true;
		if (o == null || getClass() != o.getClass())
			return false;
		UserDetailsImpl user = (UserDetailsImpl) o;
		return Objects.equals(this.getId(), user.getId());
	}


}
