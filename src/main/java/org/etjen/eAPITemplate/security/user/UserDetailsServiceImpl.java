package org.etjen.eAPITemplate.security.user;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.*;
import org.springframework.stereotype.Service;
import org.etjen.eAPITemplate.domain.model.User;
import org.etjen.eAPITemplate.repository.UserRepository;

@Service
public class UserDetailsServiceImpl implements UserDetailsService {
    @Autowired private UserRepository userRepo;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userRepo.findByUsername(username);
        if (user == null){
            System.out.println("User not found.");
            throw new UsernameNotFoundException("User not found.");
        }
        return new UserPrincipal(user);
    }
}