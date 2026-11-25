package com.iam.service;

import com.iam.dto.request.PermissionRequest;
import com.iam.dto.response.PageResponse;
import com.iam.dto.response.PermissionResponse;
import com.iam.entity.Permission;
import com.iam.exception.AppException;
import com.iam.exception.ErrorCode;
import com.iam.repository.PermissionRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
@Slf4j
public class PermissionService {

    private final PermissionRepository permissionRepository;

    public PageResponse<PermissionResponse> getPermissions(String keyword, Pageable pageable) {
        Page<Permission> page = permissionRepository.searchPermissions(keyword, pageable);
        return PageResponse.from(page.map(this::mapToResponse));
    }

    public PermissionResponse getPermissionById(Long id) {
        Permission permission = permissionRepository.findById(id)
                .orElseThrow(() -> new AppException(ErrorCode.PERMISSION_NOT_FOUND));
        return mapToResponse(permission);
    }

    @Transactional
    public PermissionResponse createPermission(PermissionRequest request) {
        if (permissionRepository.existsByCode(request.getCode())) {
            throw new AppException(ErrorCode.PERMISSION_EXISTED);
        }

        Permission permission = Permission.builder()
                .code(request.getCode().trim().toUpperCase())
                .name(request.getName().trim())
                .resource(request.getResource().trim().toUpperCase())
                .action(request.getAction().trim().toUpperCase())
                .description(request.getDescription())
                .build();

        Permission saved = permissionRepository.save(permission);
        log.info("Created permission: code={}", saved.getCode());
        return mapToResponse(saved);
    }

    @Transactional
    public PermissionResponse updatePermission(Long id, PermissionRequest request) {
        Permission permission = permissionRepository.findById(id)
                .orElseThrow(() -> new AppException(ErrorCode.PERMISSION_NOT_FOUND));

        permission.setName(request.getName().trim());
        permission.setResource(request.getResource().trim().toUpperCase());
        permission.setAction(request.getAction().trim().toUpperCase());
        permission.setDescription(request.getDescription());

        Permission updated = permissionRepository.save(permission);
        log.info("Updated permission: id={}, code={}", id, updated.getCode());
        return mapToResponse(updated);
    }

    @Transactional
    public void deletePermission(Long id) {
        Permission permission = permissionRepository.findById(id)
                .orElseThrow(() -> new AppException(ErrorCode.PERMISSION_NOT_FOUND));
        permissionRepository.delete(permission);
        log.info("Soft-deleted permission: id={}, code={}", id, permission.getCode());
    }

    public PermissionResponse mapToResponse(Permission p) {
        return PermissionResponse.builder()
                .id(p.getId())
                .code(p.getCode())
                .name(p.getName())
                .resource(p.getResource())
                .action(p.getAction())
                .description(p.getDescription())
                .createdAt(p.getCreatedAt())
                .createdBy(p.getCreatedBy())
                .updatedAt(p.getUpdatedAt())
                .updatedBy(p.getUpdatedBy())
                .build();
    }
}
