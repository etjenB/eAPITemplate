package org.etjen.eAPITemplate.web.payload.auth;

public record TokenPair(String accessToken, String refreshToken) {}