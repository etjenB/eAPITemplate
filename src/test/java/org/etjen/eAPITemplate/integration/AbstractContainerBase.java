package org.etjen.eAPITemplate.integration;

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
}
