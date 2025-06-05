package org.etjen.eAPITemplate.service.custom;

import org.etjen.eAPITemplate.domain.model.User;
import org.etjen.eAPITemplate.exception.auth.CustomUnauthorizedExpection;
import org.etjen.eAPITemplate.repository.UserRepository;
import org.etjen.eAPITemplate.security.jwt.JwtService;
import org.etjen.eAPITemplate.security.user.UserPrincipal;
import org.etjen.eAPITemplate.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Service;

import java.util.Collection;
import java.util.List;

@Service
public class UserServiceImpl implements UserService {
    private final UserRepository userRepository;
    private final AuthenticationManager authenticationManager;
    private final JwtService jwtService;

    @Autowired
    public UserServiceImpl(UserRepository userRepository, AuthenticationManager authenticationManager, JwtService jwtService) {
        this.userRepository = userRepository;
        this.authenticationManager = authenticationManager;
        this.jwtService = jwtService;
    }

    @Override
    public User save(User user) {
        return userRepository.save(user);
    }

    @Override
    public String login(String username, String password) throws CustomUnauthorizedExpection {
        try{
            Authentication auth = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(username, password)
            );
            UserPrincipal p = (UserPrincipal) auth.getPrincipal();
            List<String> roles = p.getAuthorities().stream()
                    .map(GrantedAuthority::getAuthority)
                    .toList();
            return jwtService.generateToken(username, roles);
        } catch (AuthenticationException ex) {
            throw new CustomUnauthorizedExpection(ex.getMessage());
        }
    }
}
