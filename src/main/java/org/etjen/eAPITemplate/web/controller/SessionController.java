package org.etjen.eAPITemplate.web.controller;

import lombok.RequiredArgsConstructor;
import org.etjen.eAPITemplate.security.user.UserPrincipal;
import org.etjen.eAPITemplate.service.SessionService;
import org.etjen.eAPITemplate.web.payload.session.SessionDto;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;
import java.util.List;

@RestController
@RequestMapping(value = "/auth/sessions", produces = "application/json")
@RequiredArgsConstructor
public class SessionController {
    private final SessionService sessionService;

    @GetMapping
    public ResponseEntity<List<SessionDto>> getSessions(@AuthenticationPrincipal UserPrincipal userPrincipal) {
        return ResponseEntity.ok(sessionService.list(userPrincipal.getId()));
    }

    @GetMapping("/{tokenId}")
    public ResponseEntity<SessionDto> getSession(@AuthenticationPrincipal UserPrincipal userPrincipal, @PathVariable String tokenId) {
        return ResponseEntity.ok(sessionService.get(userPrincipal.getId(), tokenId));
    }

    @DeleteMapping("/{tokenId}")
    public ResponseEntity<Void> revokeSession(@AuthenticationPrincipal UserPrincipal userPrincipal, @PathVariable String tokenId) {
        sessionService.revoke(userPrincipal.getId(), tokenId);
        return ResponseEntity.noContent().build();
    }

    @DeleteMapping
    public ResponseEntity<Void> revokeAllSessions(@AuthenticationPrincipal UserPrincipal userPrincipal) {
        sessionService.revokeAll(userPrincipal.getId());
        return ResponseEntity.noContent().build();
    }
}
