package com.together.auth.services;

import com.twilio.Twilio;
import com.twilio.rest.api.v2010.account.Message;
import com.twilio.type.PhoneNumber;
import jakarta.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

@Slf4j
@Service
public class SmsService {

    @Value("${twilio.account-sid:}")
    private String accountSid;

    @Value("${twilio.auth-token:}")
    private String authToken;

    @Value("${twilio.phone-number:}")
    private String twilioPhoneNumber;

    @Value("${twilio.mock-enabled:true}")
    private boolean mockEnabled;

    @PostConstruct
    public void init() {
        if (!mockEnabled && !accountSid.isBlank()) {
            Twilio.init(accountSid, authToken);
            log.info("Twilio initialized with account: {}", accountSid);
        } else {
            log.info("SMS service running in MOCK mode — real SMS will NOT be sent");
        }
    }

    public void sendOtp(String phoneNumber, String otpCode) {
        String messageText = String.format("Your verification code: %s\nValid for 5 minutes.", otpCode);

        if (mockEnabled) {
            // В режиме разработки просто логируем код
            log.info("═══════════════════════════════════");
            log.info("  [MOCK SMS] To: {}", phoneNumber);
            log.info("  OTP Code:  {}", otpCode);
            log.info("═══════════════════════════════════");
            return;
        }

        try {
            Message message = Message.creator(
                    new PhoneNumber(phoneNumber),
                    new PhoneNumber(twilioPhoneNumber),
                    messageText
            ).create();

            log.info("SMS sent to {}, SID: {}", phoneNumber, message.getSid());
        } catch (Exception e) {
            log.error("Failed to send SMS to {}: {}", phoneNumber, e.getMessage());
            throw new RuntimeException("Failed to send SMS", e);
        }
    }
}
