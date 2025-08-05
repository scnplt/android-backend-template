package dev.sertan.android.backend.controller;

import dev.sertan.android.backend.model.User;
import dev.sertan.android.backend.service.AuthService;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/auth")
public class AuthController {

    private final AuthService authService;

    public AuthController(AuthService authService) {
        this.authService = authService;
    }

    @PostMapping("/register")
    public Boolean register(@RequestBody AuthRequest request) {
        User user = authService.register(request.email, request.password);
        return user != null;
    }

    @PostMapping("/login")
    public AuthService.TokenResponse login(@RequestBody AuthRequest request) {
        return authService.login(request.email, request.password);
    }

    @PostMapping("/refresh")
    public AuthService.TokenResponse refresh(@RequestBody RefreshRequest request) {
        return authService.refresh(request.refreshToken);
    }

    public record AuthRequest(String email, String password) {
    }

    public record RefreshRequest(String refreshToken) {
    }
}
