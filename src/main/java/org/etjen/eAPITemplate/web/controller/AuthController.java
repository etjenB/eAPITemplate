package org.etjen.eAPITemplate.web.controller;

import org.etjen.eAPITemplate.domain.model.User;
import org.etjen.eAPITemplate.exception.auth.CustomUnauthorizedExpection;
import org.etjen.eAPITemplate.service.UserService;
import org.etjen.eAPITemplate.web.payload.auth.LoginRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/auth")
public class AuthController {
    private final UserService userService;

    @Autowired
    public AuthController(UserService userService) {
        this.userService = userService;
    }

    @PostMapping("/register")
    public User register(@RequestBody User u) {
        return userService.save(u);
    }

    @PostMapping("/login")
    public ResponseEntity<String> login(@RequestBody LoginRequest loginRequest) throws CustomUnauthorizedExpection {
        return new ResponseEntity<>(userService.login(loginRequest.getUsername(), loginRequest.getPassword()), HttpStatus.OK);
    }
}
