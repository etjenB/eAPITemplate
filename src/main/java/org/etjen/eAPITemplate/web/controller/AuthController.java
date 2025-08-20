package org.etjen.eAPITemplate.web.controller;

import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.etjen.eAPITemplate.config.properties.security.JwtProperties;
import org.etjen.eAPITemplate.exception.auth.CustomUnauthorizedException;
import org.etjen.eAPITemplate.security.jwt.JwtService;
import org.etjen.eAPITemplate.service.UserService;
import org.etjen.eAPITemplate.web.payload.auth.LoginRequest;
import org.etjen.eAPITemplate.web.payload.auth.LoginResponse;
import org.etjen.eAPITemplate.web.payload.auth.RegistrationRequest;
import org.etjen.eAPITemplate.web.payload.auth.TokenPair;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import java.time.Duration;
import java.time.Instant;

@RestController
@RequestMapping(value = "/auth", produces = "application/json")
@RequiredArgsConstructor
public class AuthController {
    private final UserService userService;
    private final JwtService jwtService;
    private final JwtProperties jwtProperties;

    // ? don't need this because lombok @RequiredArgsConstructor annotation
    // @Autowired
    // public AuthController(UserService userService) {
    //     this.userService = userService;
    // }

    @PostMapping("/register")
    public ResponseEntity<Void> register(@Valid @RequestBody RegistrationRequest registrationRequest) {
        userService.register(registrationRequest);
        return ResponseEntity.status(HttpStatus.CREATED).build();
    }

    @GetMapping("/verify")
    public ResponseEntity<Void> verify(@RequestParam String token) {
        userService.verify(token);
        return ResponseEntity.status(HttpStatus.NO_CONTENT).build();
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
    public ResponseEntity<LoginResponse> login(@RequestParam(name = "revokeOldest", defaultValue = "false", required = false) boolean revokeOldest,
                                                @Valid @RequestBody LoginRequest loginRequest) throws CustomUnauthorizedException {
        TokenPair pair = userService.login(loginRequest.username(), loginRequest.password(), revokeOldest);
        ResponseCookie cookie = buildRefreshCookie(pair.refreshToken());
        return ResponseEntity.ok()
                .header(HttpHeaders.SET_COOKIE, cookie.toString())
                .body(new LoginResponse(pair.accessToken(), jwtProperties.expiration().toMillis(), "Bearer")); // ? pair.refreshToken() - this would be done for mobile app clients
    }

    @PostMapping("/refresh")
    public ResponseEntity<LoginResponse> refresh(@CookieValue("refresh_token") String refreshJwt
                                               // ? @RequestBody(required = false) Map<String,String> body - this would be collected from mobile app clients: {"refresh_token": "..."}
    ) {
        TokenPair pair = userService.refresh(refreshJwt);
        ResponseCookie cookie = buildRefreshCookie(pair.refreshToken());
        return ResponseEntity.ok()
                .header(HttpHeaders.SET_COOKIE, cookie.toString())
                .body(new LoginResponse(pair.accessToken(), jwtProperties.expiration().toMillis(), "Bearer"));
    }

    private ResponseCookie buildRefreshCookie(String refreshToken) {
        Instant exp = jwtService.extractExpiration(refreshToken).toInstant();
        long seconds = Duration.between(Instant.now(), exp)
                .minusSeconds(5) // small skew buffer
                .toSeconds();
        if (seconds < 0) seconds = 0;

        // put refresh token into an HttpOnly, Secure cookie
        return ResponseCookie.from("refresh_token", refreshToken)
                .httpOnly(true)
                .secure(true)
                .sameSite("Strict")
                .path("/auth")
                .maxAge(Duration.ofSeconds(seconds))
                .build();
    }
}
