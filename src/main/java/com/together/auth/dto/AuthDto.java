package com.together.auth.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import lombok.Data;

// ── Запрос на отправку OTP ──────────────────────────────────────────────────
public class AuthDto {

    @Data
    public static class SendOtpRequest {
        @NotBlank(message = "Phone number is required")
        @Pattern(
                regexp = "^\\+[1-9]\\d{6,14}$",
                message = "Phone number must be in E.164 format, e.g. +79001234567"
        )
        private String phoneNumber;
    }

    // ── Запрос на верификацию OTP ───────────────────────────────────────────
    @Data
    public static class VerifyOtpRequest {
        @NotBlank(message = "Phone number is required")
        @Pattern(regexp = "^\\+[1-9]\\d{6,14}$")
        private String phoneNumber;

        @NotBlank(message = "OTP code is required")
        @Pattern(regexp = "^\\d{4,8}$", message = "OTP must be 4-8 digits")
        private String otpCode;
    }

    // ── Ответ с токенами ────────────────────────────────────────────────────
    @Data
    @lombok.Builder
    @lombok.AllArgsConstructor
    @lombok.NoArgsConstructor
    public static class AuthResponse {
        private String accessToken;
        private String refreshToken;
        private String tokenType;
        private long expiresIn;
        @JsonProperty("isNewUser")
        private boolean isNewUser;
        private UserInfo user;
    }

    // ── Инфо о пользователе ─────────────────────────────────────────────────
    @Data
    @lombok.Builder
    @lombok.AllArgsConstructor
    @lombok.NoArgsConstructor
    public static class UserInfo {
        private Long id;
        private String phoneNumber;
    }

    // ── Запрос обновления токена ────────────────────────────────────────────
    @Data
    public static class RefreshTokenRequest {
        @NotBlank
        private String refreshToken;
    }

    // ── Ответ на отправку OTP ───────────────────────────────────────────────
    @Data
    @lombok.Builder
    @lombok.AllArgsConstructor
    @lombok.NoArgsConstructor
    public static class SendOtpResponse {
        private String message;
        private int ttlMinutes;
        private String phoneNumber;
    }
}
