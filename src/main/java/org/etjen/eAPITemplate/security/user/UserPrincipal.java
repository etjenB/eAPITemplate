package org.etjen.eAPITemplate.security.user;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.etjen.eAPITemplate.domain.model.User;
import java.time.Instant;
import java.util.Collection;
import java.util.stream.Collectors;

public class UserPrincipal implements UserDetails {
    private final User user;
    public UserPrincipal(User user) { this.user = user; }
    @Override public Collection<? extends GrantedAuthority> getAuthorities()
    {
        return user.getRoles().stream().map(role -> new SimpleGrantedAuthority(role.getName())).collect(Collectors.toSet());
    }

    public Long getId() {
        return user.getId();
    }
    @Override public String getPassword() {
        return user.getPassword();
    }

    @Override public String getUsername() {
        return user.getUsername();
    }

    @Override
    public boolean isAccountNonExpired() {
        return user.isAccountNonExpired();
    }

    @Override
    public boolean isAccountNonLocked() {
        return user.isAccountNonLocked();
    }

    public Instant getLockedUntil() {
        return user.getLockedUntil();
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return user.isCredentialsNonExpired();
    }

    @Override
    public boolean isEnabled() {
        return user.isEnabled();
    }
}