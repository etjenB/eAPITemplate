package org.etjen.eAPITemplate.domain.model;

import jakarta.persistence.*;
import lombok.Data;

@Data
@Entity
@Table(name = "roles")
public class Role {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private int id;
    // ! We store roles in uppercase, with a “ROLE_” prefix to follow Spring’s convention.
    @Column(nullable = false, unique = true)
    private String name;
}