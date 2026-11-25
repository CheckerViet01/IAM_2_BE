package com.iam.dto.request;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.*;

import java.util.Set;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class UserCreateRequest {

    private String username;

    @NotBlank(message = "Email không được để trống")
    @Email(message = "Email không đúng định dạng")
    private String email;

    @NotBlank(message = "Mật khẩu không được để trống")
    @Size(min = 6, message = "Mật khẩu tối thiểu 6 ký tự")
    private String password;

    private String fullName;

    private String phoneNumber;

    private Set<String> roleCodes;

    private Set<String> roles;

    public String getEffectiveUsername() {
        return (username != null && !username.isBlank()) ? username.trim() : (email != null ? email.trim() : "");
    }

    public Set<String> getEffectiveRoleCodes() {
        if (roleCodes != null && !roleCodes.isEmpty()) return roleCodes;
        if (roles != null && !roles.isEmpty()) return roles;
        return Set.of();
    }
}
