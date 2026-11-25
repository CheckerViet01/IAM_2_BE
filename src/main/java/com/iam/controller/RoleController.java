package com.iam.controller;

import com.iam.dto.request.AssignPermissionsRequest;
import com.iam.dto.request.RoleRequest;
import com.iam.dto.response.ApiResponse;
import com.iam.dto.response.PageResponse;
import com.iam.dto.response.RoleResponse;
import com.iam.entity.Permission;
import com.iam.repository.PermissionRepository;
import com.iam.service.RoleService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Pageable;
import org.springframework.data.web.PageableDefault;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

@RestController
@RequestMapping({"/api/roles", "/api/v1/roles"})
@RequiredArgsConstructor
@Tag(name = "Phân quyền - Vai trò (Roles)", description = "Các API CRUD quản lý vai trò và gán quyền trong RBAC")
public class RoleController {

    private final RoleService roleService;
    private final PermissionRepository permissionRepository;

    @GetMapping
    @PreAuthorize("hasPermission('ROLE', 'READ')")
    @Operation(summary = "Xem danh sách vai trò (hỗ trợ tìm kiếm và phân trang)")
    public ApiResponse<PageResponse<RoleResponse>> getRoles(
            @RequestParam(required = false) String keyword,
            @PageableDefault(size = 10) Pageable pageable) {
        return ApiResponse.ok(roleService.getRoles(keyword, pageable));
    }

    @GetMapping("/{id}")
    @PreAuthorize("hasPermission('ROLE', 'READ')")
    @Operation(summary = "Xem chi tiết vai trò theo ID")
    public ApiResponse<RoleResponse> getRoleById(@PathVariable Long id) {
        return ApiResponse.ok(roleService.getRoleById(id));
    }

    @PostMapping
    @PreAuthorize("hasPermission('ROLE', 'CREATE')")
    @Operation(summary = "Tạo mới vai trò")
    public ApiResponse<RoleResponse> createRole(@Valid @RequestBody RoleRequest request) {
        return ApiResponse.ok("Tạo vai trò thành công", roleService.createRole(request));
    }

    @PutMapping("/{id}")
    @PreAuthorize("hasPermission('ROLE', 'UPDATE')")
    @Operation(summary = "Cập nhật vai trò")
    public ApiResponse<RoleResponse> updateRole(
            @PathVariable Long id,
            @Valid @RequestBody RoleRequest request) {
        return ApiResponse.ok("Cập nhật vai trò thành công", roleService.updateRole(id, request));
    }

    @DeleteMapping("/{id}")
    @PreAuthorize("hasPermission('ROLE', 'DELETE')")
    @Operation(summary = "Xóa mềm vai trò")
    public ApiResponse<Void> deleteRole(@PathVariable Long id) {
        roleService.deleteRole(id);
        return ApiResponse.ok("Xóa mềm vai trò thành công", null);
    }

    @PostMapping("/{id}/permissions")
    @PreAuthorize("hasPermission('ROLE', 'ASSIGN_PERMISSION')")
    @Operation(summary = "Gán quyền cho vai trò")
    public ApiResponse<RoleResponse> assignPermissions(
            @PathVariable Long id,
            @Valid @RequestBody AssignPermissionsRequest request) {
        return ApiResponse.ok("Gán quyền cho vai trò thành công", roleService.assignPermissions(id, request));
    }

    @PutMapping("/{id}/permissions")
    @PreAuthorize("hasPermission('ROLE', 'ASSIGN_PERMISSION')")
    @Operation(summary = "Gán quyền cho vai trò (Hỗ trợ danh sách ID quyền từ Frontend)")
    public ApiResponse<RoleResponse> assignPermissionsPut(
            @PathVariable Long id,
            @RequestBody List<Long> permissionIds) {
        List<Permission> perms = permissionRepository.findAllById(permissionIds != null ? permissionIds : List.of());
        Set<String> codes = perms.stream().map(Permission::getCode).collect(Collectors.toSet());
        AssignPermissionsRequest req = AssignPermissionsRequest.builder().permissionCodes(codes).build();
        return ApiResponse.ok("Gán quyền cho vai trò thành công", roleService.assignPermissions(id, req));
    }
}
