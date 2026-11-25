package com.iam.service.impl;

import com.iam.dto.request.LoginRequest;
import com.iam.dto.request.LogoutRequest;
import com.iam.dto.request.RefreshTokenRequest;
import com.iam.dto.request.RegisterRequest;
import com.iam.dto.response.LoginResponse;
import com.iam.dto.response.TokenResponse;
import com.iam.entity.RefreshToken;
import com.iam.entity.Role;
import com.iam.entity.User;
import com.iam.exception.AppException;
import com.iam.exception.ErrorCode;
import com.iam.repository.RefreshTokenRepository;
import com.iam.repository.RoleRepository;
import com.iam.repository.UserRepository;
import com.iam.security.CustomUserDetails;
import com.iam.security.JwtTokenProvider;
import com.iam.service.AuthService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.HashSet;
import java.util.Optional;
import java.util.Set;

@Service
@ConditionalOnProperty(name = "app.idp.provider", havingValue = "self")
@RequiredArgsConstructor
@Slf4j
public class SelfAuthServiceImpl implements AuthService {

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final RefreshTokenRepository refreshTokenRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtTokenProvider jwtTokenProvider;
    private final AuthenticationManager authenticationManager;

    @Override
    @Transactional
    public LoginResponse login(LoginRequest request) {
        log.info("Processing login in SELF-IDP mode for user={}", request.getUsername());

        if (request.getUsername() == null || request.getPassword() == null) {
            throw new AppException(ErrorCode.INVALID_CREDENTIALS, "Vui lòng nhập đầy đủ tên đăng nhập và mật khẩu");
        }

        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(request.getUsername().trim(), request.getPassword())
        );

        SecurityContextHolder.getContext().setAuthentication(authentication);

        CustomUserDetails userDetails = (CustomUserDetails) authentication.getPrincipal();
        User user = userDetails.getUser();

        // Cập nhật lastLoginAt
        user.setLastLoginAt(LocalDateTime.now());
        userRepository.save(user);

        // Sinh Access Token và Refresh Token nội bộ
        String accessToken = jwtTokenProvider.generateAccessToken(authentication);
        String refreshTokenStr = jwtTokenProvider.generateRefreshToken(user.getUsername());

        // Lưu Refresh Token vào Database
        RefreshToken refreshToken = RefreshToken.builder()
                .userId(user.getId())
                .token(refreshTokenStr)
                .expiresAt(LocalDateTime.now().plusDays(7))
                .revoked(false)
                .build();
        refreshTokenRepository.save(refreshToken);

        return LoginResponse.builder()
                .message("Đăng nhập thành công qua Self-IDP!")
                .provider("SELF")
                .accessToken(accessToken)
                .refreshToken(refreshTokenStr)
                .tokenType("Bearer")
                .expiresIn(jwtTokenProvider.getJwtExpirationInMs() / 1000)
                .username(user.getUsername())
                .build();
    }

    @Override
    @Transactional
    public LoginResponse register(RegisterRequest request) {
        log.info("Processing register in SELF-IDP mode for user={}", request.getUsername());

        if (userRepository.existsByUsername(request.getUsername()) || userRepository.existsByEmail(request.getEmail())) {
            throw new AppException(ErrorCode.USER_EXISTED);
        }

        Set<Role> roles = new HashSet<>();
        Optional<Role> defaultRole = roleRepository.findByCode("USER");
        defaultRole.ifPresent(roles::add);

        User user = User.builder()
                .username(request.getUsername().trim())
                .email(request.getEmail().trim())
                .passwordHash(passwordEncoder.encode(request.getPassword()))
                .fullName(request.getFullName())
                .phoneNumber(request.getPhoneNumber())
                .authProvider("LOCAL")
                .locked(false)
                .enabled(true)
                .roles(roles)
                .build();

        userRepository.save(user);

        return LoginResponse.builder()
                .message("Đăng ký tài khoản thành công trên Self-IDP!")
                .provider("SELF")
                .username(user.getUsername())
                .build();
    }

    @Override
    @Transactional
    public TokenResponse refreshToken(RefreshTokenRequest request) {
        log.info("Refreshing token via Self-IDP");

        String tokenStr = request.getRefreshToken();
        if (!jwtTokenProvider.validateToken(tokenStr)) {
            throw new AppException(ErrorCode.TOKEN_INVALID);
        }

        RefreshToken refreshToken = refreshTokenRepository.findByTokenAndRevokedFalse(tokenStr)
                .orElseThrow(() -> new AppException(ErrorCode.TOKEN_INVALID, "Refresh token không tồn tại hoặc đã bị thu hồi"));

        if (refreshToken.getExpiresAt().isBefore(LocalDateTime.now())) {
            throw new AppException(ErrorCode.TOKEN_EXPIRED);
        }

        User user = userRepository.findById(refreshToken.getUserId())
                .orElseThrow(() -> new AppException(ErrorCode.USER_NOT_FOUND));

        CustomUserDetails userDetails = CustomUserDetails.build(user);
        UsernamePasswordAuthenticationToken auth =
                new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());

        String newAccessToken = jwtTokenProvider.generateAccessToken(auth);

        return TokenResponse.builder()
                .accessToken(newAccessToken)
                .refreshToken(tokenStr)
                .tokenType("Bearer")
                .expiresIn(jwtTokenProvider.getJwtExpirationInMs() / 1000)
                .build();
    }

    @Override
    @Transactional
    public void logout(LogoutRequest request) {
        log.info("Logging out from Self-IDP");
        if (request != null && request.getRefreshToken() != null) {
            refreshTokenRepository.findByTokenAndRevokedFalse(request.getRefreshToken())
                    .ifPresent(rt -> {
                        rt.setRevoked(true);
                        refreshTokenRepository.save(rt);
                    });
        }
    }
}
