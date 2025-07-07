package org.etjen.eAPITemplate.web.controller;

import jakarta.validation.Valid;
import org.etjen.eAPITemplate.domain.model.User;
import org.etjen.eAPITemplate.exception.auth.CustomUnauthorizedExpection;
import org.etjen.eAPITemplate.service.UserService;
import org.etjen.eAPITemplate.web.payload.auth.LoginRequest;
import org.etjen.eAPITemplate.web.payload.auth.LoginResponse;
import org.etjen.eAPITemplate.web.payload.auth.TokenPair;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import java.time.Duration;

@RestController
@RequestMapping("/auth")
public class AuthController {
    private final UserService userService;
    @Value("${security.jwt.expirationMs}")
    private long jwtExpirationMs;
    @Value("${security.jwt.refreshExpirationMs}")
    private long jwtRefreshExpirationMs;

    @Autowired
    public AuthController(UserService userService) {
        this.userService = userService;
    }

    @PostMapping("/register")
    public User register(@Valid @RequestBody User u) {
        return userService.save(u);
    }

    @PostMapping("/logout")
    public ResponseEntity<Void> logout(@CookieValue(value = "refresh_token", required = false) String refreshJwt,
                                       @RequestHeader(value = "X-Refresh-Token", required = false) String headerRt
                                       // ? @RequestBody(required = false) Map<String,String> body - this would be collected from mobile app clients: {"refresh_token": "..."}
    ) {
        String refreshToken = refreshJwt != null ? refreshJwt : headerRt;
        if (refreshToken != null) {
            userService.logout(refreshToken);
        }

        ResponseCookie delete = ResponseCookie.from("refresh_token", "")
                .httpOnly(true)
                .secure(true)
                .sameSite("Strict")
                .path("/auth")
                .maxAge(0)
                .build();

        return ResponseEntity.noContent()
                .header(HttpHeaders.SET_COOKIE, delete.toString())
                .build();
    }

    @PostMapping("/login")
    public ResponseEntity<LoginResponse> login(@Valid @RequestBody LoginRequest loginRequest) throws CustomUnauthorizedExpection {
        TokenPair pair = userService.login(loginRequest.getUsername(), loginRequest.getPassword());
        // put refresh token into an HttpOnly, Secure cookie
        ResponseCookie cookie = ResponseCookie.from("refresh_token", pair.refreshToken())
                .httpOnly(true)
                .secure(true)
                .sameSite("Strict")
                .path("/auth")
                .maxAge(Duration.ofMillis(jwtRefreshExpirationMs))
                .build();
        LoginResponse body = new LoginResponse(
                pair.accessToken(),
                jwtExpirationMs,
                "Bearer"
                // ? pair.refreshToken() - this would be done for mobile app clients
        );
        return ResponseEntity.ok()
                .header(HttpHeaders.SET_COOKIE, cookie.toString())
                .body(body);
    }

    @PostMapping("/refresh")
    public ResponseEntity<LoginResponse> refresh(@CookieValue("refresh_token") String refreshJwt
                                               // ? @RequestBody(required = false) Map<String,String> body - this would be collected from mobile app clients: {"refresh_token": "..."}
    ) {
        TokenPair pair = userService.refresh(refreshJwt);

        ResponseCookie cookie = ResponseCookie.from("refresh_token", pair.refreshToken())
                .httpOnly(true)
                .secure(true)
                .sameSite("Strict")
                .path("/auth")
                .maxAge(Duration.ofMillis(jwtRefreshExpirationMs))
                .build();

        LoginResponse body = new LoginResponse(
                pair.accessToken(),
                jwtExpirationMs,
                "Bearer"
                // ? pair.refreshToken() - this would be done for mobile app clients
        );

        return ResponseEntity.ok()
                .header(HttpHeaders.SET_COOKIE, cookie.toString())
                .body(body);
    }
}
