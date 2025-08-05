package dev.sertan.android.backend.service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import lombok.Getter;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.util.Date;

@Service
public class JwtService {

    private static final String CLAIM_TYP = "typ";

    @Value("${jwt.secret}")
    private String jwtSecret;

    @Value("${jwt.validityMs.access}")
    private Long accessTokenValidityMs;

    @Getter
    @Value("${jwt.validityMs.refresh}")
    private Long refreshTokenValidityMs;

    private SecretKey secretKey;

    @PostConstruct
    public void init() {
        secretKey = Keys.hmacShaKeyFor(jwtSecret.getBytes());
    }

    private String generateToken(String userId, String type, Long expiry) {
        Date now = new Date();
        Date expiration = new Date(now.getTime() + expiry);

        return Jwts.builder()
                .subject(userId)
                .claim(CLAIM_TYP, type)
                .issuedAt(now)
                .expiration(expiration)
                .signWith(secretKey, Jwts.SIG.HS256)
                .compact();
    }

    public String generateRefreshToken(String userId) {
        return generateToken(userId, Type.REFRESH.name(), refreshTokenValidityMs);
    }

    public String generateAccessToken(String userId) {
        return generateToken(userId, Type.ACCESS.name(), accessTokenValidityMs);
    }

    public Boolean validateAccessToken(String token) {
        return getTypeFromToken(token) == Type.ACCESS;
    }

    public Boolean validateRefreshToken(String token) {
        return getTypeFromToken(token) == Type.REFRESH;
    }

    private Type getTypeFromToken(String token) {
        try {
            Claims claims = extractAllClaims(token);
            if (claims == null) return null;
            return Type.valueOf(claims.get(CLAIM_TYP).toString());
        } catch (IllegalArgumentException exception) {
            throw new BadCredentialsException("Invalid credentials.");
        }
    }

    public String getUserIdFromToken(String token) {
        Claims claims = extractAllClaims(token);
        if (claims == null) return null;
        return claims.getSubject();
    }

    private Claims extractAllClaims(String token) {
        return Jwts.parser()
                .verifyWith(secretKey)
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    public enum Type {
        ACCESS,
        REFRESH;
    }
}
