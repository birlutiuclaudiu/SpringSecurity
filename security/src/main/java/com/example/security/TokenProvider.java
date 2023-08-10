package com.example.security;


import com.example.model.User;
import io.jsonwebtoken.*;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.io.Serializable;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Component
@Slf4j
public class TokenProvider implements Serializable {


    private static final long serialVersionUID = 1L;

    private final TokenProperties tokenProperties;

    @Autowired
    public TokenProvider(TokenProperties tokenProperties) {
        this.tokenProperties = tokenProperties;
    }

    /**
     * This method construct the token at authentication
     *
     * @param user the energy user who is authenticated
     * @return a string which represents the token generated
     */
    public String provideToken(User user) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("email", user.getEmail());
        claims.put("id", user.getId());
        claims.put("role", user.getRole().name());
        Date issuedDate = new Date(System.currentTimeMillis());
        Date expirationDate = new Date(System.currentTimeMillis() + tokenProperties.getTokenValidity());
        return Jwts.builder()
                .setClaims(claims)
                .setSubject(user.getEmail())
                .setIssuedAt(issuedDate)
                .setExpiration(expirationDate)
                .signWith(SignatureAlgorithm.HS512, tokenProperties.getTokenSecret())
                .compact();
    }

    public String extractUsername(String token) {
        Claims claims = null;
        try {
            claims = Jwts.parser().setSigningKey(tokenProperties.getTokenSecret()).parseClaimsJws(token).getBody();
            System.out.println(claims.get("email"));
            return claims.getSubject();
        } catch (MalformedJwtException ex) {
            throw new RuntimeException(ex.getMessage());
        }
    }

    public <T> T getClaimFromToken(String token, Function<Claims, T> claimsTFunction) {
        Claims claims = null;
        try {
            claims = Jwts.parser().setSigningKey(tokenProperties.getTokenSecret()).parseClaimsJws(token).getBody();
        } catch (MalformedJwtException ex) {
            throw new RuntimeException(ex.getMessage());
        }

        return claimsTFunction.apply(claims);
    }

    public boolean validateToken(String token) {
        if (token == null) return false;
        try {
            Jwts.parser().setSigningKey(tokenProperties.getTokenSecret()).parseClaimsJws(token);
            return true;
        } catch (SignatureException e) {
            log.info("Invalid JWT signature.");
            log.trace("Invalid JWT signature trace: {}", e);
        } catch (MalformedJwtException e) {
            log.info("Invalid JWT token.");
            log.trace("Invalid JWT token trace: {}", e);
        } catch (ExpiredJwtException e) {
            log.info("Expired JWT token.");
            log.trace("Expired JWT token trace: {}", e);
        } catch (UnsupportedJwtException e) {
            log.info("Unsupported JWT token.");
            log.trace("Unsupported JWT token trace: {}", e);
        } catch (IllegalArgumentException e) {
            log.info("JWT token compact of handler are invalid.");
            log.trace("JWT token compact of handler are invalid trace: {}", e);
        }
        return false;
    }

}