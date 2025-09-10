package org.etjen.eAPITemplate.integration;

import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.containers.PostgreSQLContainer;

public abstract class AbstractContainerBase {
    static final PostgreSQLContainer postgresSqlContainer;
    static {
        postgresSqlContainer = new PostgreSQLContainer("postgres:latest")
                .withDatabaseName("eapitemplatetests")
                .withUsername("postgres")
                .withPassword("0000");
        postgresSqlContainer.start();
    }

    @DynamicPropertySource
    static void registerProps(DynamicPropertyRegistry r) {
        r.add("spring.datasource.url", postgresSqlContainer::getJdbcUrl);
        r.add("spring.datasource.username", postgresSqlContainer::getUsername);
        r.add("spring.datasource.password", postgresSqlContainer::getPassword);

        // Keep Flyway pointed to the same DB (prevents any ambiguity)
        r.add("spring.flyway.url", postgresSqlContainer::getJdbcUrl);
        r.add("spring.flyway.user", postgresSqlContainer::getUsername);
        r.add("spring.flyway.password", postgresSqlContainer::getPassword);
    }
}
