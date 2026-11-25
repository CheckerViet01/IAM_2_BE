package com.iam.dto.request;

import lombok.*;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class LoginRequest {

    // Cho phép để trống khi người dùng chỉ gọi /login để lấy link đăng nhập Keycloak
    private String username;

    private String password;
}
