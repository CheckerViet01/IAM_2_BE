package com.iam.service.impl;

import com.iam.dto.request.LoginRequest;
import com.iam.dto.request.LogoutRequest;
import com.iam.dto.request.RefreshTokenRequest;
import com.iam.dto.request.RegisterRequest;
import com.iam.dto.response.LoginResponse;
import com.iam.dto.response.TokenResponse;
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

import java.util.HashSet;
import java.util.Optional;
import java.util.Set;

@Service
@ConditionalOnProperty(name = "app.idp.provider", havingValue = "keycloak", matchIfMissing = true)
@RequiredArgsConstructor
@Slf4j
public class KeycloakAuthServiceImpl implements AuthService {

    private final KeycloakAdminService keycloakAdminService;
    private final UserRepository userRepository;
    private final RoleRepository roleRepository;

    @Override
    public LoginResponse login(LoginRequest request) {
        log.info("Processing login in KEYCLOAK mode");

        // Nếu client cung cấp username & password trực tiếp -> Đăng nhập lấy Bearer token ngay
        if (request != null && request.getUsername() != null && !request.getUsername().isBlank()
                && request.getPassword() != null && !request.getPassword().isBlank()) {
            TokenResponse tokenResponse = keycloakAdminService.loginDirect(request.getUsername(), request.getPassword());
            return LoginResponse.builder()
                    .message("Đăng nhập Keycloak thành công!")
                    .provider("KEYCLOAK")
                    .accessToken(tokenResponse.getAccessToken())
                    .refreshToken(tokenResponse.getRefreshToken())
                    .tokenType(tokenResponse.getTokenType())
                    .expiresIn(tokenResponse.getExpiresIn())
                    .username(request.getUsername())
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
        log.info("Processing register in KEYCLOAK mode for username={}, email={}", request.getUsername(), request.getEmail());

        if (userRepository.existsByUsername(request.getUsername()) || userRepository.existsByEmail(request.getEmail())) {
            throw new AppException(ErrorCode.USER_EXISTED);
        }

        // 1. Tạo tài khoản trên Keycloak
        String keycloakId = keycloakAdminService.createUser(
                request.getUsername().trim(),
                request.getEmail().trim(),
                request.getPassword(),
                request.getFullName()
        );

        // 2. Đồng bộ lưu vào Database nội bộ của IAM
        Set<Role> roles = new HashSet<>();
        Optional<Role> defaultRole = roleRepository.findByCode("USER");
        defaultRole.ifPresent(roles::add);

        User user = User.builder()
                .username(request.getUsername().trim())
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
