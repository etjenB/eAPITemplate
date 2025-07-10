package org.etjen.eAPITemplate.domain.model;

import jakarta.persistence.*;
import lombok.Data;
import org.etjen.eAPITemplate.domain.model.enums.AccountStatus;
import java.time.Instant;
import java.util.HashSet;
import java.util.Set;

@Data
@Entity
@Table(name = "users")
public class User {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    @Column(nullable = false, unique = true)
    private String username;
    @Column(nullable = false, unique = true)
    private String email;
    private String password;
    private boolean accountNonExpired = true;
    private boolean accountNonLocked = true;
    private Integer failedLoginAttempts = 0;
    private Instant lockedUntil = null;
    private boolean credentialsNonExpired = true;
    private boolean enabled = true;
    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private AccountStatus status;
    @Column(nullable = false)
    private boolean emailVerified = false;

    @ManyToMany(fetch = FetchType.EAGER)
    @JoinTable(
        name = "users_roles",
        joinColumns = @JoinColumn(name = "user_id"),
        inverseJoinColumns = @JoinColumn(name = "role_id")
    )
    private Set<Role> roles = new HashSet<>();
}
