package org.etjen.eAPITemplate.domain.model;

import jakarta.persistence.*;
import lombok.*;

import java.time.Instant;

@Data
@Entity
@NoArgsConstructor
@AllArgsConstructor
@Builder
@EqualsAndHashCode(onlyExplicitlyIncluded = true)
@Table(name = "refresh_tokens",
        indexes = {
                @Index(name = "idx_rt_token_id", columnList = "token_id", unique = true),
                @Index(name = "idx_rt_user_id",  columnList = "user_id")
        })
public class RefreshToken {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @EqualsAndHashCode.Include
    private Long id;
    @Column(nullable = false, unique = true, length = 36)
    private String tokenId;
    @Column(nullable = false)
    private Instant expiresAt;
    /** Single-use rotation: once the client swaps this token for a new pair, set revoked = true. */
    @Column(nullable = false)
    @Builder.Default private boolean revoked = false;
    /** Optional metadata – useful for auditing or “list my devices” endpoints. */
    @Column(nullable = false)
    private Instant issuedAt;
    private String ipAddress;
    private String userAgent;

    /** Owning side of the relation – many refresh tokens per user. */
    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "user_id")
    private User user;
}
