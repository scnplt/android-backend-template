package dev.sertan.android.backend.repository;

import dev.sertan.android.backend.model.RefreshToken;
import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface RefreshTokenRepository extends MongoRepository<RefreshToken, String> {
    RefreshToken findByUserIdAndHashedToken(String userId, String hashedToken);

    void deleteByUserIdAndHashedToken(String userId, String hashedToken);
}
