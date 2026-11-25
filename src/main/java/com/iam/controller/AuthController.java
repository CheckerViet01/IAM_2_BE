package com.iam.controller;

import com.iam.dto.request.LoginRequest;
import com.iam.dto.request.LogoutRequest;
import com.iam.dto.request.RefreshTokenRequest;
import com.iam.dto.request.RegisterRequest;
import com.iam.dto.response.ApiResponse;
import com.iam.dto.response.LoginResponse;
import com.iam.dto.response.TokenResponse;
import com.iam.entity.PasswordResetToken;
import com.iam.entity.Role;
import com.iam.entity.User;
import com.iam.exception.AppException;
import com.iam.exception.ErrorCode;
import com.iam.repository.PasswordResetTokenRepository;
import com.iam.repository.UserRepository;
import com.iam.security.JwtTokenProvider;
import com.iam.service.AuthService;
import com.iam.service.EmailService;
import com.iam.service.KeycloakAdminService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@RestController
@RequestMapping({"/api/auth", "/api/v1/auth"})
@RequiredArgsConstructor
@Slf4j
@Tag(name = "Xác thực & Danh tính (Authentication)", description = "Các API Đăng nhập, Đăng ký, Refresh Token, Đăng xuất hỗ trợ Dual-IDP")
public class AuthController {

    private final AuthService authService;
    private final KeycloakAdminService keycloakAdminService;
    private final UserRepository userRepository;
    private final PasswordResetTokenRepository passwordResetTokenRepository;
    private final EmailService emailService;
    private final PasswordEncoder passwordEncoder;
    private final JwtTokenProvider jwtTokenProvider;

    @Value("${app.idp.provider:keycloak}")
    private String idpProvider;

    @Value("${app.keycloak.auth-server-url:http://localhost:8180}")
    private String keycloakServerUrl;

    @Value("${app.keycloak.realm:iam-realm}")
    private String keycloakRealm;

    @Value("${app.keycloak.client-id:iam-frontend}")
    private String keycloakClientId;

    @GetMapping("/keycloak-config")
    @Operation(summary = "Lấy cấu hình Identity Server Keycloak cho Frontend")
    public ApiResponse<Map<String, Object>> getKeycloakConfig() {
        Map<String, Object> config = new HashMap<>();
        config.put("enabled", "keycloak".equalsIgnoreCase(idpProvider));
        config.put("serverUrl", keycloakServerUrl);
        config.put("realm", keycloakRealm);
        config.put("clientId", keycloakClientId);
        config.put("loginUrl", keycloakAdminService.getLoginPageUrl());
        return ApiResponse.ok(config);
    }

    @PostMapping("/login")
    @Operation(summary = "Đăng nhập hệ thống (Keycloak: trả về link login hoặc token direct; Self-IDP: xác thực DB & cấp JWT)")
    public ApiResponse<LoginResponse> login(@RequestBody(required = false) LoginRequest request) {
        return ApiResponse.ok("Xử lý đăng nhập thành công", authService.login(request));
    }

    @PostMapping("/register")
    @Operation(summary = "Đăng ký người dùng mới (Keycloak: tạo trên Keycloak & sync DB; Self-IDP: tạo trong DB)")
    public ApiResponse<LoginResponse> register(@Valid @RequestBody RegisterRequest request) {
        return ApiResponse.ok("Đăng ký thành công", authService.register(request));
    }

    @PostMapping("/refresh-token")
    @Operation(summary = "Làm mới Access Token (Từ Keycloak hoặc Self-IDP)")
    public ApiResponse<TokenResponse> refreshToken(@Valid @RequestBody RefreshTokenRequest request) {
        return ApiResponse.ok("Làm mới token thành công", authService.refreshToken(request));
    }

    @PostMapping("/logout")
    @Operation(summary = "Đăng xuất tài khoản (Thu hồi token trên Keycloak hoặc Self-IDP)")
    public ApiResponse<Void> logout(@RequestBody(required = false) LogoutRequest request) {
        authService.logout(request);
        return ApiResponse.ok("Đăng xuất thành công", null);
    }

    @PostMapping("/forgot-password")
    @Operation(summary = "Yêu cầu mã OTP đặt lại mật khẩu gửi về Email")
    @Transactional
    public ApiResponse<String> forgotPassword(@RequestBody Map<String, String> body) {
        String email = body != null ? body.get("email") : null;
        if (email == null || email.isBlank()) {
            throw new AppException(ErrorCode.INVALID_REQUEST, "Email không được để trống!");
        }

        User user = userRepository.findByEmail(email.trim())
                .or(() -> userRepository.findByUsername(email.trim()))
                .orElseThrow(() -> new AppException(ErrorCode.USER_NOT_FOUND, "Không tìm thấy tài khoản với email " + email));

        String otp = String.format("%06d", new java.util.Random().nextInt(1000000));
        String tokenStr = "FORGOT:" + user.getId() + ":" + otp;

        PasswordResetToken token = PasswordResetToken.builder()
                .userId(user.getId())
                .token(tokenStr)
                .expiresAt(LocalDateTime.now().plusMinutes(5))
                .used(false)
                .build();
        passwordResetTokenRepository.save(token);

        emailService.sendOtpEmail(
                user.getEmail(),
                otp,
                "Mã OTP Đặt Lại Mật Khẩu - IAM Verse",
                "Khôi Phục Mật Khẩu",
                "Bạn đã gửi yêu cầu đặt lại mật khẩu cho tài khoản <strong>" + user.getEmail() + "</strong>."
        );

        return ApiResponse.ok("Mã OTP đã được gửi đến email " + user.getEmail() + " ✨", otp);
    }

    @PostMapping("/reset-password")
    @Operation(summary = "Đặt lại mật khẩu bằng mã OTP đã nhận qua Email")
    @Transactional
    public ApiResponse<String> resetPasswordWithOtp(@RequestBody Map<String, String> body) {
        String email = body != null ? body.get("email") : null;
        String otpCode = body != null ? body.get("otpCode") : null;
        String newPassword = body != null ? body.get("newPassword") : null;

        if (email == null || email.isBlank() || otpCode == null || otpCode.isBlank() || newPassword == null || newPassword.isBlank()) {
            throw new AppException(ErrorCode.INVALID_REQUEST, "Vui lòng nhập đầy đủ email, mã OTP và mật khẩu mới!");
        }

        User user = userRepository.findByEmail(email.trim())
                .or(() -> userRepository.findByUsername(email.trim()))
                .orElseThrow(() -> new AppException(ErrorCode.USER_NOT_FOUND, "Không tìm thấy tài khoản với email này!"));

        String expectedToken = "FORGOT:" + user.getId() + ":" + otpCode.trim();
        PasswordResetToken token = passwordResetTokenRepository.findByTokenAndUsedFalse(expectedToken)
                .orElseThrow(() -> new AppException(ErrorCode.INVALID_REQUEST, "Mã OTP không đúng hoặc đã được sử dụng!"));

        if (token.getExpiresAt().isBefore(LocalDateTime.now())) {
            throw new AppException(ErrorCode.INVALID_REQUEST, "Mã OTP đã hết hạn, vui lòng yêu cầu mã mới!");
        }

        token.setUsed(true);
        passwordResetTokenRepository.save(token);

        // Đổi mật khẩu trong DB nội bộ
        user.setPasswordHash(passwordEncoder.encode(newPassword));
        userRepository.save(user);

        // Đồng bộ lên Keycloak nếu có Keycloak ID hoặc tìm thấy trên Keycloak
        String kId = user.getKeycloakId();
        if (kId == null || kId.isBlank()) {
            kId = keycloakAdminService.findUserIdByUsernameOrEmail(user.getUsername(), user.getEmail());
            if (kId != null) {
                user.setKeycloakId(kId);
                userRepository.save(user);
            }
        }
        if (kId != null && !kId.isBlank()) {
            try {
                keycloakAdminService.resetPassword(kId, newPassword);
            } catch (Exception ex) {
                log.warn("Failed to sync reset password to Keycloak: {}", ex.getMessage());
            }
        }

        return ApiResponse.ok("Đặt lại mật khẩu thành công! Hãy đăng nhập với mật khẩu mới ✨", "SUCCESS");
    }

    @PostMapping("/verify-2fa")
    @Operation(summary = "Xác thực OTP 2FA sau khi đăng nhập")
    @Transactional
    public ApiResponse<LoginResponse> verify2fa(@RequestBody Map<String, String> body) {
        String email = body != null ? body.get("email") : null;
        String otpCode = body != null ? body.get("otpCode") : null;

        if (email == null || otpCode == null) {
            throw new AppException(ErrorCode.INVALID_REQUEST, "Email và mã OTP không được để trống");
        }

        User user = userRepository.findByEmail(email.trim())
                .or(() -> userRepository.findByUsername(email.trim()))
                .orElseThrow(() -> new AppException(ErrorCode.USER_NOT_FOUND, "Không tìm thấy người dùng"));

        String expectedToken = "2FA_LOGIN:" + user.getId() + ":" + otpCode.trim();
        PasswordResetToken token = passwordResetTokenRepository.findByTokenAndUsedFalse(expectedToken)
                .orElseThrow(() -> new AppException(ErrorCode.INVALID_REQUEST, "Mã OTP không chính xác hoặc đã hết hạn!"));

        if (token.getExpiresAt().isBefore(LocalDateTime.now())) {
            throw new AppException(ErrorCode.INVALID_REQUEST, "Mã OTP đã hết hạn, vui lòng đăng nhập lại!");
        }

        token.setUsed(true);
        passwordResetTokenRepository.save(token);

        String authorities = user.getRoles() != null
                ? user.getRoles().stream().map(Role::getCode).collect(Collectors.joining(","))
                : "ROLE_USER";
        String accessToken = jwtTokenProvider.generateAccessToken(user.getUsername(), authorities);
        String refreshToken = jwtTokenProvider.generateRefreshToken(user.getUsername());

        Map<String, Object> userProfile = new HashMap<>();
        userProfile.put("id", user.getId());
        userProfile.put("username", user.getUsername());
        userProfile.put("email", user.getEmail());
        userProfile.put("fullName", user.getFullName() != null ? user.getFullName() : user.getUsername());
        userProfile.put("isActive", user.isEnabled() && !user.isDeleted());
        userProfile.put("isLocked", user.isLocked());
        userProfile.put("twoFactorEnabled", user.isTwoFactorEnabled());
        userProfile.put("twoFactorMethod", "EMAIL");
        userProfile.put("roles", user.getRoles() != null ? user.getRoles().stream().map(Role::getCode).collect(Collectors.toList()) : List.of("USER"));

        LoginResponse resp = LoginResponse.builder()
                .message("Xác thực 2FA thành công!")
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .tokenType("Bearer")
                .expiresIn(3600L)
                .username(user.getUsername())
                .user(userProfile)
                .build();

        return ApiResponse.ok("Xác thực 2FA thành công!", resp);
    }
}
