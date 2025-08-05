package dev.sertan.android.backend.security;

import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Component;

@Component
public class HashEncoder {

    private final BCryptPasswordEncoder encoder;

    public HashEncoder() {
        encoder = new BCryptPasswordEncoder();
    }

    public String encode(String raw) {
        return encoder.encode(raw);
    }

    public boolean matches(String raw, String hashed) {
        return encoder.matches(raw, hashed);
    }
}
