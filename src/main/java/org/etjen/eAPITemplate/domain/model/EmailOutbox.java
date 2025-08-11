package org.etjen.eAPITemplate.domain.model;

import jakarta.persistence.*;
import lombok.*;
import org.etjen.eAPITemplate.domain.model.enums.MailStatus;
import java.time.Instant;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@Entity
@EqualsAndHashCode(onlyExplicitlyIncluded = true)
@Table(name = "email_outbox")
public class EmailOutbox {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @EqualsAndHashCode.Include
    private Long id;
    @Column(nullable = false)
    private Long aggregateId;
    @Column(nullable = false)
    private String toAddress;
    @Column(nullable = false)
    private String subject;
    @Column(nullable = false)
    private String body;
    @Column(nullable = false)
    @Builder.Default private Instant createdAt = Instant.now();
    private Instant sentAt;
    @Enumerated(EnumType.STRING)
    @Builder.Default private MailStatus status = MailStatus.PENDING;
    @Builder.Default private Integer attempts = 0;
    private String lastError;

    public void markSent() {
        this.status = MailStatus.SENT;
        this.sentAt = Instant.now();
    }
}
