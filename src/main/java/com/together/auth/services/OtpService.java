package com.together.auth.services;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import java.security.SecureRandom;
import java.time.Duration;

@Slf4j
@Service
@RequiredArgsConstructor
public class OtpService {

    private static final String OTP_KEY_PREFIX      = "otp:";
    private static final String ATTEMPTS_KEY_PREFIX = "otp:attempts:";

    private final StringRedisTemplate redisTemplate;

    @Value("${otp.length:6}")
    private int otpLength;

    @Value("${otp.ttl-minutes:5}")
    private int ttlMinutes;

    @Value("${otp.max-attempts:3}")
    private int maxAttempts;

    // ── Генерация и сохранение OTP ──────────────────────────────────────────
    public String generateAndStore(String phoneNumber) {
        String otp = generateOtp();

        String otpKey      = OTP_KEY_PREFIX + phoneNumber;
        String attemptsKey = ATTEMPTS_KEY_PREFIX + phoneNumber;

        // Сохраняем OTP и сбрасываем счётчик попыток
        redisTemplate.opsForValue().set(otpKey, otp, Duration.ofMinutes(ttlMinutes));
        redisTemplate.delete(attemptsKey);

        log.debug("OTP generated for {}: {} (TTL {} min)", phoneNumber, otp, ttlMinutes);
        return otp;
    }

    // ── Верификация OTP ─────────────────────────────────────────────────────
    public OtpVerificationResult verify(String phoneNumber, String inputOtp) {
        String otpKey      = OTP_KEY_PREFIX + phoneNumber;
        String attemptsKey = ATTEMPTS_KEY_PREFIX + phoneNumber;

        String storedOtp = redisTemplate.opsForValue().get(otpKey);

        if (storedOtp == null) {
            return OtpVerificationResult.EXPIRED;
        }

        // Проверяем количество попыток
        String attemptsStr = redisTemplate.opsForValue().get(attemptsKey);
        int attempts = attemptsStr != null ? Integer.parseInt(attemptsStr) : 0;

        if (attempts >= maxAttempts) {
            redisTemplate.delete(otpKey);
            return OtpVerificationResult.MAX_ATTEMPTS_EXCEEDED;
        }

        if (!storedOtp.equals(inputOtp)) {
            // Увеличиваем счётчик попыток
            redisTemplate.opsForValue().increment(attemptsKey);
            redisTemplate.expire(attemptsKey, Duration.ofMinutes(ttlMinutes));
            return OtpVerificationResult.INVALID;
        }

        // OTP верный — удаляем из Redis
        redisTemplate.delete(otpKey);
        redisTemplate.delete(attemptsKey);
        return OtpVerificationResult.SUCCESS;
    }

    // ── Генерация числового OTP ─────────────────────────────────────────────
    private String generateOtp() {
        SecureRandom random = new SecureRandom();
        int max = (int) Math.pow(10, otpLength);
        int otp = random.nextInt(max);
        return String.format("%0" + otpLength + "d", otp);
    }

    public int getTtlMinutes() {
        return ttlMinutes;
    }

    public enum OtpVerificationResult {
        SUCCESS,
        INVALID,
        EXPIRED,
        MAX_ATTEMPTS_EXCEEDED
    }
}
