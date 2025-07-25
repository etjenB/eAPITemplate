package org.etjen.eAPITemplate.domain.model;

import jakarta.persistence.*;
import lombok.*;
import java.time.Instant;

@Entity
@Builder
@Table(name = "email_verification_tokens")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class EmailVerificationToken {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    @Column(nullable = false, unique = true)
    private String token; // UUIDv4
    @Column(nullable = false)
    private Instant expiresAt;
    @Column(nullable = false)
    @Builder.Default private boolean used = false;
    @Column(nullable = false)
    private Instant issuedAt;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "user_id")
    private User user;
}
