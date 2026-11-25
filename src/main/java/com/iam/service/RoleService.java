package com.iam.service;

import com.iam.dto.request.AssignPermissionsRequest;
import com.iam.dto.request.RoleRequest;
import com.iam.dto.response.PageResponse;
import com.iam.dto.response.RoleResponse;
import com.iam.entity.Permission;
import com.iam.entity.Role;
import com.iam.exception.AppException;
import com.iam.exception.ErrorCode;
import com.iam.repository.PermissionRepository;
import com.iam.repository.RoleRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
@Slf4j
public class RoleService {

    private final RoleRepository roleRepository;
    private final PermissionRepository permissionRepository;
    private final PermissionService permissionService;

    public PageResponse<RoleResponse> getRoles(String keyword, Pageable pageable) {
        Page<Role> page = roleRepository.searchRoles(keyword, pageable);
        return PageResponse.from(page.map(this::mapToResponse));
    }

    public RoleResponse getRoleById(Long id) {
        Role role = roleRepository.findById(id)
                .orElseThrow(() -> new AppException(ErrorCode.ROLE_NOT_FOUND));
        return mapToResponse(role);
    }

    @Transactional
    public RoleResponse createRole(RoleRequest request) {
        String code = request.getEffectiveCode();
        if (roleRepository.existsByCode(code)) {
            throw new AppException(ErrorCode.ROLE_EXISTED);
        }

        Role role = Role.builder()
                .code(code)
                .name(request.getName().trim())
                .description(request.getDescription())
                .system(false)
                .build();

        Role saved = roleRepository.save(role);
        log.info("Created role: code={}", saved.getCode());
        return mapToResponse(saved);
    }

    @Transactional
    public RoleResponse updateRole(Long id, RoleRequest request) {
        Role role = roleRepository.findById(id)
                .orElseThrow(() -> new AppException(ErrorCode.ROLE_NOT_FOUND));

        role.setName(request.getName().trim());
        role.setDescription(request.getDescription());

        Role updated = roleRepository.save(role);
        log.info("Updated role: id={}, code={}", id, updated.getCode());
        return mapToResponse(updated);
    }

    @Transactional
    public void deleteRole(Long id) {
        Role role = roleRepository.findById(id)
                .orElseThrow(() -> new AppException(ErrorCode.ROLE_NOT_FOUND));

        if (role.isSystem()) {
            throw new AppException(ErrorCode.CANNOT_DELETE_SYSTEM_ROLE);
        }

        roleRepository.delete(role);
        log.info("Soft-deleted role: id={}, code={}", id, role.getCode());
    }

    @Transactional
    public RoleResponse assignPermissions(Long roleId, AssignPermissionsRequest request) {
        Role role = roleRepository.findById(roleId)
                .orElseThrow(() -> new AppException(ErrorCode.ROLE_NOT_FOUND));

        List<Permission> permissions = permissionRepository.findByCodeIn(request.getPermissionCodes());
        role.setPermissions(new HashSet<>(permissions));

        Role saved = roleRepository.save(role);
        log.info("Assigned {} permissions to role: {}", permissions.size(), saved.getCode());
        return mapToResponse(saved);
    }

    public RoleResponse mapToResponse(Role role) {
        Set<com.iam.dto.response.PermissionResponse> permissionResponses = role.getPermissions() != null
                ? role.getPermissions().stream().map(permissionService::mapToResponse).collect(Collectors.toSet())
                : Set.of();

        return RoleResponse.builder()
                .id(role.getId())
                .code(role.getCode())
                .name(role.getName())
                .description(role.getDescription())
                .system(role.isSystem())
                .permissions(permissionResponses)
                .createdAt(role.getCreatedAt())
                .createdBy(role.getCreatedBy())
                .updatedAt(role.getUpdatedAt())
                .updatedBy(role.getUpdatedBy())
                .build();
    }
}
