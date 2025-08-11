package org.etjen.eAPITemplate.domain.model;

import jakarta.persistence.*;
import lombok.*;
import org.etjen.eAPITemplate.domain.model.enums.AccountStatus;
import java.time.Instant;
import java.util.HashSet;
import java.util.Set;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@Entity
@EqualsAndHashCode(onlyExplicitlyIncluded = true)
@Table(name = "users")
public class User {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @EqualsAndHashCode.Include
    private Long id;
    @Column(nullable = false, unique = true)
    private String username;
    @Column(nullable = false, unique = true)
    private String email;
    private String password;
    @Builder.Default private boolean accountNonExpired = true;
    @Builder.Default private boolean accountNonLocked = true;
    @Builder.Default private Integer failedLoginAttempts = 0;
    @Builder.Default private Instant lockedUntil = null;
    @Builder.Default private boolean credentialsNonExpired = true;
    @Builder.Default private boolean enabled = true;
    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private AccountStatus status;
    @Column(nullable = false)
    @Builder.Default private boolean emailVerified = false;

    @ManyToMany(fetch = FetchType.EAGER)
    @JoinTable(
        name = "users_roles",
        joinColumns = @JoinColumn(name = "user_id"),
        inverseJoinColumns = @JoinColumn(name = "role_id")
    )
    private Set<Role> roles = new HashSet<>();
}
