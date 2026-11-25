package com.iam.dto.request;

import jakarta.validation.constraints.NotEmpty;
import lombok.*;

import java.util.Set;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class AssignPermissionsRequest {

    @NotEmpty(message = "Danh sách mã quyền không được rỗng")
    private Set<String> permissionCodes;
}
