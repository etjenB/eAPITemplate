package org.etjen.eAPITemplate.web.mapper;

import org.etjen.eAPITemplate.domain.model.RefreshToken;
import org.etjen.eAPITemplate.web.payload.session.SessionDto;
import org.mapstruct.Context;
import org.mapstruct.Mapper;
import org.mapstruct.Mapping;
import java.util.List;

@Mapper(componentModel = "spring")
public interface SessionMapper {
    @Mapping(target = "current",
            expression = "java(rt.getTokenId().equals(currentJti))")
    @Mapping(target = "status",
            expression = "java(rt.isRevoked() ? SessionDto.Status.REVOKED : SessionDto.Status.ACTIVE)")
    SessionDto toDto(RefreshToken rt, @Context String currentJti);
    List<SessionDto> toDtos(List<RefreshToken> tokens, @Context String currentJti);
}
