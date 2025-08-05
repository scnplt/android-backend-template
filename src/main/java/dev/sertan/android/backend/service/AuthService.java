package dev.sertan.android.backend.service;

import dev.sertan.android.backend.model.RefreshToken;
import dev.sertan.android.backend.model.User;
import dev.sertan.android.backend.repository.RefreshTokenRepository;
import dev.sertan.android.backend.repository.UserRepository;
import dev.sertan.android.backend.security.HashEncoder;
import lombok.AllArgsConstructor;
import lombok.Data;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.Base64;

@Service
public class AuthService {

    private final JwtService jwtService;
    private final UserRepository userRepository;
    private final HashEncoder hashEncoder;
    private final RefreshTokenRepository refreshTokenRepository;

    public AuthService(
            JwtService jwtService,
            UserRepository userRepository,
            HashEncoder hashEncoder,
            RefreshTokenRepository refreshTokenRepository
    ) {
        this.jwtService = jwtService;
        this.userRepository = userRepository;
        this.hashEncoder = hashEncoder;
        this.refreshTokenRepository = refreshTokenRepository;
    }

    public User register(String email, String password) {
        return userRepository.save(new User(
                email,
                hashEncoder.encode(password)
        ));
    }

    public TokenResponse login(String email, String password) {
        User user = userRepository.findByEmail(email);

        if (user == null || !hashEncoder.matches(password, user.getHashedPassword())) {
            throw new BadCredentialsException("Invalid credentials");
        }

        String accessToken = jwtService.generateAccessToken(user.getId());
        String refreshToken = jwtService.generateRefreshToken(user.getId());

        saveRefreshToken(user.getId(), refreshToken);

        return new TokenResponse(accessToken, refreshToken);
    }

    @Transactional
    public TokenResponse refresh(String rawRefreshToken) {
        if (!jwtService.validateRefreshToken(rawRefreshToken)) {
            throw new IllegalArgumentException("Invalid refresh token");
        }

        String userId = jwtService.getUserIdFromToken(rawRefreshToken);

        User user = userRepository.findById(userId)
                .orElseThrow(() -> new IllegalArgumentException("Invalid refresh token."));

        String hashedToken = hashToken(rawRefreshToken);
        RefreshToken refreshToken = refreshTokenRepository.findByUserIdAndHashedToken(user.getId(), hashedToken);
        if (refreshToken == null) {
            throw new IllegalArgumentException("Refresh token not recognized (maybe used or expired)");
        }

        String newAccessToken = jwtService.generateAccessToken(user.getId());
        String newRefreshToken = jwtService.generateRefreshToken(user.getId());

        refreshTokenRepository.deleteByUserIdAndHashedToken(user.getId(), hashedToken);
        saveRefreshToken(user.getId(), newRefreshToken);

        return new TokenResponse(newAccessToken, newRefreshToken);
    }

    private void saveRefreshToken(String userId, String rawRefreshToken) {
        String hashedToken = hashToken(rawRefreshToken);
        Long expiryMs = jwtService.getRefreshTokenValidityMs();
        Instant expiresAt = Instant.now().plusMillis(expiryMs);
        refreshTokenRepository.save(new RefreshToken(userId, expiresAt, hashedToken));
    }

    private String hashToken(String rawToken) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hashBytes = digest.digest(rawToken.getBytes());
            return Base64.getEncoder().encodeToString(hashBytes);
        } catch (NoSuchAlgorithmException exception) {
            return null;
        }
    }

    @Data
    @AllArgsConstructor
    public static class TokenResponse {
        private final String accessToken;
        private final String refreshToken;
    }
}
