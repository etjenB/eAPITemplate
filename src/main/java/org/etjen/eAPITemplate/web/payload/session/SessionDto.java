package org.etjen.eAPITemplate.web.payload.session;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;

import java.time.Instant;

@Data
@Builder
@AllArgsConstructor
public class SessionDto {
    private String tokenId;
    private Instant issuedAt;
    private Instant expiresAt;
    private String ipAddress;
    private String  userAgent;
    private boolean current; // “this device” flag
    private Status  status;

    public enum Status { ACTIVE, REVOKED }
}
