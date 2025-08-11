package org.etjen.eAPITemplate.domain.model;

import jakarta.persistence.*;
import lombok.Data;
import lombok.EqualsAndHashCode;

@Data
@Entity
@EqualsAndHashCode(onlyExplicitlyIncluded = true)
@Table(name = "roles")
public class Role {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @EqualsAndHashCode.Include
    private int id;
    // ! We store roles in uppercase, with a “ROLE_” prefix to follow Spring’s convention.
    @Column(nullable = false, unique = true)
    private String name;
}