package org.etjen.eAPITemplate.repository;

import org.etjen.eAPITemplate.domain.model.User;
import org.etjen.eAPITemplate.domain.model.enums.AccountStatus;
import org.springframework.data.jpa.repository.JpaRepository;
import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Long> {
    Optional<User> findByUsername(String username);
    boolean existsByEmailIgnoreCaseAndStatus(String email, AccountStatus status);
    boolean existsByUsernameIgnoreCase(String username);
}
