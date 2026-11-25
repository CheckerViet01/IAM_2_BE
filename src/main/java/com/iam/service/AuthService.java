package com.iam.service;

import com.iam.dto.request.LoginRequest;
import com.iam.dto.request.LogoutRequest;
import com.iam.dto.request.RefreshTokenRequest;
import com.iam.dto.request.RegisterRequest;
import com.iam.dto.response.LoginResponse;
import com.iam.dto.response.TokenResponse;

public interface AuthService {

    LoginResponse login(LoginRequest request);

    LoginResponse register(RegisterRequest request);

    TokenResponse refreshToken(RefreshTokenRequest request);

    void logout(LogoutRequest request);
}
