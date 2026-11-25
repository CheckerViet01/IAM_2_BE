package com.iam.dto.request;

import jakarta.validation.constraints.NotBlank;
import lombok.*;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class PermissionRequest {

    private String code;

    @NotBlank(message = "Tên quyền không được để trống")
    private String name;

    private String module;

    private String resource;

    private String action;

    private String description;

    public String getEffectiveResource() {
        if (resource != null && !resource.isBlank()) return resource.trim().toUpperCase();
        if (module != null && !module.isBlank()) return module.trim().toUpperCase();
        if (name != null && name.contains(":")) return name.split(":")[0].trim().toUpperCase();
        return "SYSTEM";
    }

    public String getEffectiveAction() {
        if (action != null && !action.isBlank()) return action.trim().toUpperCase();
        if (name != null && name.contains(":")) {
            String[] parts = name.split(":");
            return parts.length > 1 ? parts[1].trim().toUpperCase() : "ACCESS";
        }
        if (name != null && !name.isBlank()) return name.trim().toUpperCase().replaceAll("[^A-Z0-9_]+", "_");
        return "ACCESS";
    }

    public String getEffectiveCode() {
        if (code != null && !code.isBlank()) return code.trim().toUpperCase();
        return getEffectiveResource() + ":" + getEffectiveAction();
    }
}
