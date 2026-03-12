package com.together.auth.controllers;

import com.together.auth.dto.AuthDto;
import com.together.auth.services.AuthService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@Slf4j
@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;

    /**
     * POST /api/auth/send-otp
     * Отправить OTP на номер телефона
     */
    @PostMapping("/send-otp")
    public ResponseEntity<AuthDto.SendOtpResponse> sendOtp(
            @Valid @RequestBody AuthDto.SendOtpRequest request) {

        AuthDto.SendOtpResponse response = authService.sendOtp(request.getPhoneNumber());
        return ResponseEntity.ok(response);
    }

    /**
     * POST /api/auth/verify-otp
     * Верифицировать OTP → получить JWT токены
     */
    @PostMapping("/verify-otp")
    public ResponseEntity<AuthDto.AuthResponse> verifyOtp(
            @Valid @RequestBody AuthDto.VerifyOtpRequest request) {

        AuthDto.AuthResponse response = authService.verifyOtp(
                request.getPhoneNumber(),
                request.getOtpCode()
        );
        return ResponseEntity.ok(response);
    }

    /**
     * POST /api/auth/refresh
     * Обновить access token по refresh token
     */
    @PostMapping("/refresh")
    public ResponseEntity<AuthDto.AuthResponse> refreshToken(
            @Valid @RequestBody AuthDto.RefreshTokenRequest request) {

        AuthDto.AuthResponse response = authService.refreshToken(request.getRefreshToken());
        return ResponseEntity.ok(response);
    }

    /**
     * GET /api/auth/health
     * Health check
     */
    @GetMapping("/health")
    public ResponseEntity<Map<String, String>> health() {
        return ResponseEntity.ok(Map.of("status", "UP", "service", "auth-service"));
    }
}
