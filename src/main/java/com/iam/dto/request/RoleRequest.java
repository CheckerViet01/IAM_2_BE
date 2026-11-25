package com.iam.dto.request;

import jakarta.validation.constraints.NotBlank;
import lombok.*;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class RoleRequest {

    @NotBlank(message = "Mã vai trò không được để trống")
    private String code;

    @NotBlank(message = "Tên vai trò không được để trống")
    private String name;

    private String description;
}
