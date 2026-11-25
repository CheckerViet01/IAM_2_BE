package com.iam.controller;

import com.iam.dto.request.LoginRequest;
import com.iam.dto.request.LogoutRequest;
import com.iam.dto.request.RefreshTokenRequest;
import com.iam.dto.request.RegisterRequest;
import com.iam.dto.response.ApiResponse;
import com.iam.dto.response.LoginResponse;
import com.iam.dto.response.TokenResponse;
import com.iam.service.AuthService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
@Tag(name = "Xác thực & Danh tính (Authentication)", description = "Các API Đăng nhập, Đăng ký, Refresh Token, Đăng xuất hỗ trợ Dual-IDP")
public class AuthController {

    private final AuthService authService;

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
}
