package dev.sertan.android.backend.model;

import lombok.Getter;
import org.springframework.data.mongodb.core.index.Indexed;
import org.springframework.data.mongodb.core.mapping.Document;

import java.time.Instant;

@Getter
@Document("refresh_tokens")
public class RefreshToken {

    @Indexed(expireAfter = "0s")
    private final Instant expiresAt;

    private final String userId;
    private final Instant createdAt;
    private final String hashedToken;

    public RefreshToken(String userId, Instant expiresAt, String hashedToken) {
        this.userId = userId;
        this.expiresAt = expiresAt;
        this.hashedToken = hashedToken;
        createdAt = Instant.now();
    }
}
