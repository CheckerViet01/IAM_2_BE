package com.iam.service;

import com.iam.dto.response.TokenResponse;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Quản lý phiên token tạm thời khi đăng nhập yêu cầu xác thực 2 bước (2FA).
 * Sau khi người dùng xác thực OTP thành công, token chính chủ (Keycloak/Self)
 * sẽ được trả về nguyên vẹn để người dùng đăng nhập vào hệ thống ngay lập tức.
 */
@Component
public class TwoFactorSessionManager {

    private static class SessionEntry {
        final TokenResponse tokenResponse;
        final LocalDateTime expiresAt;

        SessionEntry(TokenResponse tokenResponse, LocalDateTime expiresAt) {
            this.tokenResponse = tokenResponse;
            this.expiresAt = expiresAt;
        }
    }

    private final Map<String, SessionEntry> sessionStore = new ConcurrentHashMap<>();

    public void storeSession(String tokenKey, TokenResponse tokenResponse, int expiryMinutes) {
        if (tokenKey != null && tokenResponse != null) {
            sessionStore.put(tokenKey, new SessionEntry(tokenResponse, LocalDateTime.now().plusMinutes(expiryMinutes)));
        }
    }

    public TokenResponse retrieveAndRemove(String tokenKey) {
        if (tokenKey == null) return null;
        SessionEntry entry = sessionStore.remove(tokenKey);
        if (entry != null && entry.expiresAt.isAfter(LocalDateTime.now())) {
            return entry.tokenResponse;
        }
        return null;
    }
}
