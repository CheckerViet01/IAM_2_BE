package com.iam.dto.response;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.*;

import java.util.Map;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
@JsonInclude(JsonInclude.Include.NON_NULL)
public class LoginResponse {

    private String message;
    private String provider; // KEYCLOAK hoặc SELF
    private String loginUrl; // Link đăng nhập Keycloak khi bật Keycloak
    private Boolean requires2fa;
    private String accessToken;
    private String refreshToken;
    private String tokenType;
    private Long expiresIn;
    private String username;
    private Map<String, Object> user;
}
