package dev.sertan.android.backend.model;

import lombok.Getter;
import lombok.NoArgsConstructor;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;

import java.util.UUID;

@Getter
@NoArgsConstructor
@Document("users")
public class User {
    @Id
    private String id;
    private String email;
    private String hashedPassword;

    public User(String email, String hashedPassword) {
        id = UUID.randomUUID().toString();
        this.email = email;
        this.hashedPassword = hashedPassword;
    }
}
