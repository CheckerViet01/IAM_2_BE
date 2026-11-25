package com.iam.dto.request;

import jakarta.validation.constraints.NotBlank;
import lombok.*;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class PermissionRequest {

    @NotBlank(message = "Mã quyền không được để trống")
    private String code;

    @NotBlank(message = "Tên quyền không được để trống")
    private String name;

    @NotBlank(message = "Tài nguyên (resource) không được để trống")
    private String resource;

    @NotBlank(message = "Hành động (action) không được để trống")
    private String action;

    private String description;
}
