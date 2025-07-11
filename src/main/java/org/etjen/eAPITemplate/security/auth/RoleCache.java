package org.etjen.eAPITemplate.security.auth;

import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import org.etjen.eAPITemplate.domain.model.Role;
import org.etjen.eAPITemplate.domain.model.enums.AppRole;
import org.etjen.eAPITemplate.repository.RoleRepository;
import org.springframework.stereotype.Component;
import java.util.EnumMap;

@Component
@RequiredArgsConstructor
public class RoleCache {
    private final RoleRepository roleRepository;
    private final EnumMap<AppRole, Role> map = new EnumMap<>(AppRole.class);
    @PostConstruct
    void load() {
        for (AppRole r : AppRole.values())
            map.put(r, roleRepository.findByName(r.dbName()) .orElseThrow(() -> new IllegalStateException("Missing role " + r)));
    }

    public Role get(AppRole r) {
        return map.get(r);
    }
}
