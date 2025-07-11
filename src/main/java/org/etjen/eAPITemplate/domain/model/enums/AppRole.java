package org.etjen.eAPITemplate.domain.model.enums;

public enum AppRole {
    USER,
    ADMIN;

    public String dbName() {
        return "ROLE_" + name();
    }
}
