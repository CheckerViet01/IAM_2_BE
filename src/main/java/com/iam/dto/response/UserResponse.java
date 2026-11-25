package com.iam.dto.response;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.*;

import java.time.LocalDateTime;
import java.util.Set;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class UserResponse {

    private Long id;
    private String username;
    private String email;
    private String fullName;
    private String phoneNumber;
    private String avatarUrl;
    private String keycloakId;
    private String authProvider;
    private boolean locked;
    private boolean enabled;
    private LocalDateTime lastLoginAt;
    private Set<RoleResponse> roles;
    private LocalDateTime createdAt;
    private String createdBy;
    private LocalDateTime updatedAt;
    private String updatedBy;

    @JsonProperty("isLocked")
    public boolean getIsLocked() {
        return locked;
    }

    @JsonProperty("isActive")
    public boolean getIsActive() {
        return enabled;
    }
}
