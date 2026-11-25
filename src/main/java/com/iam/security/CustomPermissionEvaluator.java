package com.iam.security;

import com.iam.entity.Permission;
import com.iam.entity.Role;
import com.iam.entity.User;
import com.iam.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.access.PermissionEvaluator;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Component;

import java.io.Serializable;
import java.util.Optional;

@Component
@RequiredArgsConstructor
@Slf4j
public class CustomPermissionEvaluator implements PermissionEvaluator {

    private final UserRepository userRepository;

    @Override
    public boolean hasPermission(Authentication authentication, Object targetDomainObject, Object permission) {
        if (authentication == null || !authentication.isAuthenticated() || permission == null) {
            return false;
        }

        String requiredPermission;
        if (targetDomainObject != null && !targetDomainObject.toString().isBlank()) {
            requiredPermission = targetDomainObject + ":" + permission;
        } else {
            requiredPermission = permission.toString();
        }

        // 1. Kiểm tra nhanh qua GrantedAuthorities trong Authentication
        for (GrantedAuthority authority : authentication.getAuthorities()) {
            String auth = authority.getAuthority();
            if ("ROLE_SYSTEM_ADMIN".equalsIgnoreCase(auth) || "SYSTEM_ADMIN".equalsIgnoreCase(auth)) {
                return true; // Quản trị hệ thống có toàn quyền
            }
            if (auth.equalsIgnoreCase(requiredPermission)) {
                return true;
            }
        }

        // 2. Tra cứu trực tiếp trong Database IAM theo thông tin User
        String principalName = authentication.getName();
        Optional<User> userOpt = userRepository.findByUsername(principalName);
        if (userOpt.isEmpty()) {
            userOpt = userRepository.findByEmail(principalName);
        }

        if (userOpt.isEmpty()) {
            log.warn("Permission check failed: User '{}' not found in IAM database", principalName);
            return false;
        }

        User user = userOpt.get();
        if (user.isLocked() || user.isDeleted()) {
            log.warn("Permission check failed: User '{}' is locked or deleted", principalName);
            return false;
        }

        // Duyệt qua tất cả các Role và Permission của User
        for (Role role : user.getRoles()) {
            if ("SYSTEM_ADMIN".equalsIgnoreCase(role.getCode())) {
                return true;
            }
            for (Permission perm : role.getPermissions()) {
                if (perm.getCode().equalsIgnoreCase(requiredPermission)) {
                    return true;
                }
            }
        }

        log.debug("User '{}' does NOT have permission '{}'", principalName, requiredPermission);
        return false;
    }

    @Override
    public boolean hasPermission(Authentication authentication, Serializable targetId, String targetType, Object permission) {
        return hasPermission(authentication, targetType, permission);
    }
}
