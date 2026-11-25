package com.iam.service.impl;

import com.iam.dto.request.LoginRequest;
import com.iam.dto.request.LogoutRequest;
import com.iam.dto.request.RefreshTokenRequest;
import com.iam.dto.request.RegisterRequest;
import com.iam.dto.response.LoginResponse;
import com.iam.dto.response.TokenResponse;
import com.iam.entity.Permission;
import com.iam.entity.Role;
import com.iam.entity.User;
import com.iam.exception.AppException;
import com.iam.exception.ErrorCode;
import com.iam.repository.RoleRepository;
import com.iam.repository.UserRepository;
import com.iam.service.AuthService;
import com.iam.service.KeycloakAdminService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.*;
import java.util.stream.Collectors;

@Service
@ConditionalOnProperty(name = "app.idp.provider", havingValue = "keycloak", matchIfMissing = true)
@RequiredArgsConstructor
@Slf4j
public class KeycloakAuthServiceImpl implements AuthService {

    private final KeycloakAdminService keycloakAdminService;
    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final com.iam.repository.PasswordResetTokenRepository passwordResetTokenRepository;
    private final com.iam.service.EmailService emailService;

    @Override
    public LoginResponse login(LoginRequest request) {
        log.info("Processing login in KEYCLOAK mode");

        String target = request != null ? request.getUsernameOrEmail() : null;

        // Nếu client cung cấp username/email & password -> Đăng nhập lấy Bearer token trực tiếp
        if (target != null && !target.isBlank() && request.getPassword() != null && !request.getPassword().isBlank()) {
            TokenResponse tokenResponse = keycloakAdminService.loginDirect(target, request.getPassword());

            // Tìm thông tin User trong DB nội bộ của IAM
            Optional<User> userOpt = userRepository.findByUsername(target)
                    .or(() -> userRepository.findByEmail(target));

            if (userOpt.isPresent() && userOpt.get().isTwoFactorEnabled()) {
                User u = userOpt.get();
                String otp = String.format("%06d", new java.util.Random().nextInt(1000000));
                String tokenStr = "2FA_LOGIN:" + u.getId() + ":" + otp;
                com.iam.entity.PasswordResetToken token = com.iam.entity.PasswordResetToken.builder()
                        .userId(u.getId())
                        .token(tokenStr)
                        .expiresAt(java.time.LocalDateTime.now().plusMinutes(5))
                        .used(false)
                        .build();
                passwordResetTokenRepository.save(token);

                emailService.sendOtpEmail(
                        u.getEmail(),
                        otp,
                        "Mã OTP Đăng Nhập (2FA) - IAM Verse",
                        "Xác Thực Đăng Nhập 2FA",
                        "Tài khoản của bạn đã kích hoạt bảo vệ 2FA. Vui lòng nhập mã OTP để hoàn tất đăng nhập."
                );

                return LoginResponse.builder()
                        .requires2fa(true)
                        .message("Tài khoản đã kích hoạt 2FA. Mã OTP đã được gửi đến email " + u.getEmail())
                        .build();
            }

            Map<String, Object> userProfile = new HashMap<>();
            if (userOpt.isPresent()) {
                User u = userOpt.get();
                userProfile.put("id", u.getId());
                userProfile.put("username", u.getUsername());
                userProfile.put("email", u.getEmail());
                userProfile.put("fullName", u.getFullName() != null ? u.getFullName() : u.getUsername());
                userProfile.put("isActive", u.isEnabled() && !u.isDeleted());
                userProfile.put("isLocked", u.isLocked());
                List<String> roles = u.getRoles() != null
                        ? u.getRoles().stream().map(Role::getCode).collect(Collectors.toList())
                        : List.of("USER");
                userProfile.put("roles", roles);

                Set<String> perms = u.getRoles() != null
                        ? u.getRoles().stream()
                            .filter(r -> r.getPermissions() != null)
                            .flatMap(r -> r.getPermissions().stream().map(Permission::getCode))
                            .collect(Collectors.toSet())
                        : Set.of();
                userProfile.put("permissions", perms);
            } else {
                userProfile.put("id", 1);
                userProfile.put("username", target);
                userProfile.put("email", target);
                userProfile.put("fullName", target);
                userProfile.put("isActive", true);
                userProfile.put("isLocked", false);
                userProfile.put("roles", List.of("USER"));
                userProfile.put("permissions", List.of());
            }

            return LoginResponse.builder()
                    .message("Đăng nhập Keycloak thành công!")
                    .provider("KEYCLOAK")
                    .accessToken(tokenResponse.getAccessToken())
                    .refreshToken(tokenResponse.getRefreshToken())
                    .tokenType(tokenResponse.getTokenType())
                    .expiresIn(tokenResponse.getExpiresIn())
                    .username(target)
                    .user(userProfile)
                    .build();
        }

        // Nếu không cung cấp credentials -> Trả về thông báo yêu cầu truy cập trang đăng nhập Keycloak
        return LoginResponse.builder()
                .message("Hệ thống đang sử dụng Keycloak làm Identity Server. Vui lòng mở trình duyệt và truy cập trang đăng nhập của Keycloak để lấy Access Token.")
                .provider("KEYCLOAK")
                .loginUrl(keycloakAdminService.getLoginPageUrl())
                .build();
    }

    @Override
    @Transactional
    public LoginResponse register(RegisterRequest request) {
        String effectiveUsername = request.getEffectiveUsername();
        log.info("Processing register in KEYCLOAK mode for username={}, email={}", effectiveUsername, request.getEmail());

        if (userRepository.existsByUsername(effectiveUsername) || userRepository.existsByEmail(request.getEmail())) {
            throw new AppException(ErrorCode.USER_EXISTED);
        }

        // 1. Tạo tài khoản trên Keycloak
        String keycloakId = keycloakAdminService.createUser(
                effectiveUsername,
                request.getEmail().trim(),
                request.getPassword(),
                request.getFullName()
        );

        // 2. Đồng bộ lưu vào Database nội bộ của IAM
        Set<Role> roles = new HashSet<>();
        Optional<Role> defaultRole = roleRepository.findByCode("USER");
        defaultRole.ifPresent(roles::add);

        User user = User.builder()
                .username(effectiveUsername)
                .email(request.getEmail().trim())
                .fullName(request.getFullName())
                .phoneNumber(request.getPhoneNumber())
                .keycloakId(keycloakId)
                .authProvider("KEYCLOAK")
                .locked(false)
                .enabled(true)
                .roles(roles)
                .build();

        userRepository.save(user);
        log.info("Synchronized user to IAM database with keycloakId={}", keycloakId);

        return LoginResponse.builder()
                .message("Đăng ký tài khoản thành công trên Keycloak và đã đồng bộ vào Database nội bộ của IAM.")
                .provider("KEYCLOAK")
                .username(user.getUsername())
                .loginUrl(keycloakAdminService.getLoginPageUrl())
                .build();
    }

    @Override
    public TokenResponse refreshToken(RefreshTokenRequest request) {
        log.info("Refreshing token via Keycloak");
        return keycloakAdminService.refreshKeycloakToken(request.getRefreshToken());
    }

    @Override
    public void logout(LogoutRequest request) {
        log.info("Logging out from Keycloak");
        if (request != null && request.getRefreshToken() != null && !request.getRefreshToken().isBlank()) {
            keycloakAdminService.logoutToken(request.getRefreshToken());
        }
    }
}
