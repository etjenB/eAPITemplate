package org.etjen.eAPITemplate.repository;

import org.etjen.eAPITemplate.domain.model.User;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepository extends JpaRepository<User, Integer> {
    User findByUsername(String username);
}
