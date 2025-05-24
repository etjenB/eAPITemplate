package org.etjen.eAPITemplate.security.user;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.etjen.eAPITemplate.model.User;
import java.util.Collection;
import java.util.Collections;

public class UserPrincipal implements UserDetails {
    private final User user;
    public UserPrincipal(User user) { this.user = user; }
    @Override public Collection<? extends GrantedAuthority> getAuthorities()
    {
        return Collections.singleton(new SimpleGrantedAuthority("USER"));
        //return user.getRoles();
    }
    @Override public String getPassword() { return user.getPassword(); }
    @Override public String getUsername() { return user.getEmail(); }
    // implement isAccountNonExpired, isAccountNonLocked, isCredentialsNonExpired, isEnabled
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
        return true;
    }
}