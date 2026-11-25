package com.iam.dto.request;

import lombok.*;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class LoginRequest {

    private String username;
    private String email;
    private String password;

    public String getUsernameOrEmail() {
        if (username != null && !username.isBlank()) return username.trim();
        if (email != null && !email.isBlank()) return email.trim();
        return null;
    }
}
