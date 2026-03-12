package com.together.auth.services;

import com.together.auth.dto.AuthDto;
import com.together.auth.entity.User;
import com.together.auth.repository.UserRepository;
import com.together.auth.utils.JwtUtil;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;

@Slf4j
@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository userRepository;
    private final OtpService otpService;
    private final SmsService smsService;
    private final JwtUtil jwtUtil;

    // ── Шаг 1: Отправить OTP ───────────────────────────────────────────────
    public AuthDto.SendOtpResponse sendOtp(String phoneNumber) {
        // Генерируем и сохраняем OTP в Redis
        String otp = otpService.generateAndStore(phoneNumber);

        // Отправляем SMS (или логируем в dev-режиме)
        smsService.sendOtp(phoneNumber, otp);

        log.info("OTP sent to phone: {}", phoneNumber);
        return AuthDto.SendOtpResponse.builder()
                .message("OTP sent successfully")
                .ttlMinutes(otpService.getTtlMinutes())
                .phoneNumber(phoneNumber)
                .build();
    }

    // ── Шаг 2: Верифицировать OTP и выдать токены ──────────────────────────
    @Transactional
    public AuthDto.AuthResponse verifyOtp(String phoneNumber, String otpCode) {
        // Проверяем OTP
        OtpService.OtpVerificationResult result = otpService.verify(phoneNumber, otpCode);

        switch (result) {
            case EXPIRED ->
                    throw new IllegalArgumentException("OTP has expired. Please request a new code.");
            case MAX_ATTEMPTS_EXCEEDED ->
                    throw new IllegalArgumentException("Too many invalid attempts. Please request a new code.");
            case INVALID ->
                    throw new IllegalArgumentException("Invalid OTP code.");
            case SUCCESS -> {
                // Всё ок, продолжаем
            }
        }

        // Находим или создаём пользователя
        boolean isNewUser = !userRepository.existsByPhoneNumber(phoneNumber);
        User user = userRepository.findByPhoneNumber(phoneNumber)
                .orElseGet(() -> createUser(phoneNumber));

        // Обновляем время последнего входа
        user.setLastLoginAt(LocalDateTime.now());
        userRepository.save(user);

        // Генерируем JWT токены
        String accessToken  = jwtUtil.generateAccessToken(phoneNumber, user.getId());
        String refreshToken = jwtUtil.generateRefreshToken(phoneNumber, user.getId());

        log.info("User {} authenticated. New user: {}", phoneNumber, isNewUser);

        return AuthDto.AuthResponse.builder()
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .tokenType("Bearer")
                .expiresIn(jwtUtil.getExpiration() / 1000)
                .isNewUser(isNewUser)
                .user(AuthDto.UserInfo.builder()
                        .id(user.getId())
                        .phoneNumber(user.getPhoneNumber())
                        .build())
                .build();
    }

    // ── Обновление access token по refresh token ───────────────────────────
    public AuthDto.AuthResponse refreshToken(String refreshToken) {
        if (!jwtUtil.validateToken(refreshToken)) {
            throw new IllegalArgumentException("Invalid or expired refresh token.");
        }

        String tokenType = jwtUtil.extractTokenType(refreshToken);
        if (!"refresh".equals(tokenType)) {
            throw new IllegalArgumentException("Provided token is not a refresh token.");
        }

        String phoneNumber = jwtUtil.extractPhoneNumber(refreshToken);
        User user = userRepository.findByPhoneNumber(phoneNumber)
                .orElseThrow(() -> new IllegalArgumentException("User not found."));

        String newAccessToken  = jwtUtil.generateAccessToken(phoneNumber, user.getId());
        String newRefreshToken = jwtUtil.generateRefreshToken(phoneNumber, user.getId());

        return AuthDto.AuthResponse.builder()
                .accessToken(newAccessToken)
                .refreshToken(newRefreshToken)
                .tokenType("Bearer")
                .expiresIn(jwtUtil.getExpiration() / 1000)
                .isNewUser(false)
                .user(AuthDto.UserInfo.builder()
                        .id(user.getId())
                        .phoneNumber(user.getPhoneNumber())
                        .build())
                .build();
    }

    // ── Создание нового пользователя ────────────────────────────────────────
    private User createUser(String phoneNumber) {
        User user = User.builder()
                .phoneNumber(phoneNumber)
                .status(User.UserStatus.ACTIVE)
                .build();
        return userRepository.save(user);
    }
}
