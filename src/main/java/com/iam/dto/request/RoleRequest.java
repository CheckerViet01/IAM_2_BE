package com.iam.dto.request;

import jakarta.validation.constraints.NotBlank;
import lombok.*;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class RoleRequest {

    private String code;

    @NotBlank(message = "Tên vai trò không được để trống")
    private String name;

    private String description;

    public String getEffectiveCode() {
        if (code != null && !code.isBlank()) return code.trim().toUpperCase();
        if (name != null && !name.isBlank()) {
            String c = name.trim().toUpperCase().replaceAll("[^A-Z0-9_]+", "_");
            return c.startsWith("ROLE_") ? c : "ROLE_" + c;
        }
        return "ROLE_CUSTOM";
    }
}
