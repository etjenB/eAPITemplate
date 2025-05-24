package org.etjen.eAPITemplate.repository;

import org.etjen.eAPITemplate.model.User;
import org.springframework.data.jpa.repository.JpaRepository;

public interface IUserRepository extends JpaRepository<User, Integer> {
    User findByUsername(String username);
}
