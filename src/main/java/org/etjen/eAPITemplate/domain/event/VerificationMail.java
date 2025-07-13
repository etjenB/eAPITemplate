package org.etjen.eAPITemplate.domain.event;

public record VerificationMail(
        Long    aggregateId,
        String  toAddress,
        String  token
) { }
