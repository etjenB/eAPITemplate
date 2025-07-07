package org.etjen.eAPITemplate.security.user;

import org.etjen.eAPITemplate.exception.auth.UserNotFoundException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.*;
import org.springframework.stereotype.Service;
import org.etjen.eAPITemplate.domain.model.User;
import org.etjen.eAPITemplate.repository.UserRepository;

@Service
public class UserDetailsServiceImpl implements UserDetailsService {
    @Autowired private UserRepository userRepo;

    @Override
    public UserDetails loadUserByUsername(String username) throws UserNotFoundException {
        User user = userRepo.findByUsername(username).orElseThrow(() -> new UserNotFoundException("User " + username + " was not found"));
        return new UserPrincipal(user);
    }
}