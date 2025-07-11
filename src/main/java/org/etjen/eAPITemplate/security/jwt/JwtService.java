package org.etjen.eAPITemplate.security.jwt;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import org.etjen.eAPITemplate.config.properties.security.JwtProperties;
import org.etjen.eAPITemplate.exception.auth.jwt.JwtGenerationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;
import java.security.Key;
import java.util.*;
import java.util.function.Function;

@Service
@RequiredArgsConstructor
public class JwtService {
    private final JwtProperties jwtProperties;
    private Key signingKey;

    @PostConstruct
    private void init() {                  // build the key once
        signingKey = buildKey(jwtProperties.secret());
    }

    private Key buildKey(String secret) {
        byte[] keyBytes = Decoders.BASE64.decode(secret);
        return Keys.hmacShaKeyFor(keyBytes);
    }

    public String generateAccessToken(String username, List<String> roles, String jti) throws JwtGenerationException {
        try {
            Map<String, Object> claims = new HashMap<>();
            claims.put("roles", roles);
            return Jwts.builder()
                    .setClaims(claims)
                    .setSubject(username)
                    .setId(jti)
                    .setIssuedAt(new Date(System.currentTimeMillis()))
                    .setExpiration(new Date(System.currentTimeMillis() + jwtProperties.expiration().toMillis()))
                    .signWith(signingKey, SignatureAlgorithm.HS512)
                    .compact();
        } catch (Exception ex) {
            throw new JwtGenerationException(ex.getMessage());
        }
    }

    public String generateRefreshToken(String username, String jti) throws JwtGenerationException {
        try {
            return Jwts.builder()
                    .setSubject(username)
                    .setId(jti)
                    .setIssuedAt(new Date(System.currentTimeMillis()))
                    .setExpiration(new Date(System.currentTimeMillis() + jwtProperties.refreshExpiration().toMillis()))
                    .signWith(signingKey, SignatureAlgorithm.HS512)
                    .compact();
        } catch (Exception ex) {
            throw new JwtGenerationException(ex.getMessage());
        }
    }


    public String extractUserName(String token) {
        // extract the username from jwt token
        return extractClaim(token, Claims::getSubject);
    }

    public <T> T extractClaim(String token, Function<Claims, T> claimResolver) {
        final Claims claims = extractAllClaims(token);
        return claimResolver.apply(claims);
    }

    public Claims extractAllClaims(String token) {
        return Jwts.parser()
                .setSigningKey(signingKey)
                .build()
                .parseClaimsJws(token) // may throw ExpiredJwtException
                .getBody();
    }

    public boolean validateToken(String token, UserDetails userDetails) {
        final String userName = extractUserName(token);
        return (userName.equals(userDetails.getUsername()) && !isTokenExpired(token));
    }

    public boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    public Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }
}
