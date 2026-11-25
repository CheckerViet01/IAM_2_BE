package com.iam.controller;

import com.iam.dto.request.PermissionRequest;
import com.iam.dto.response.ApiResponse;
import com.iam.dto.response.PageResponse;
import com.iam.dto.response.PermissionResponse;
import com.iam.service.PermissionService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Pageable;
import org.springframework.data.web.PageableDefault;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping({"/api/permissions", "/api/v1/permissions"})
@RequiredArgsConstructor
@Tag(name = "Phân quyền - Quyền (Permissions)", description = "Các API CRUD quản lý quyền trong hệ thống RBAC")
public class PermissionController {

    private final PermissionService permissionService;

    @GetMapping
    @PreAuthorize("hasPermission('PERMISSION', 'READ')")
    @Operation(summary = "Xem danh sách quyền (hỗ trợ tìm kiếm và phân trang)")
    public ApiResponse<PageResponse<PermissionResponse>> getPermissions(
            @RequestParam(required = false) String keyword,
            @PageableDefault(size = 10) Pageable pageable) {
        return ApiResponse.ok(permissionService.getPermissions(keyword, pageable));
    }

    @GetMapping("/{id}")
    @PreAuthorize("hasPermission('PERMISSION', 'READ')")
    @Operation(summary = "Xem chi tiết quyền theo ID")
    public ApiResponse<PermissionResponse> getPermissionById(@PathVariable Long id) {
        return ApiResponse.ok(permissionService.getPermissionById(id));
    }

    @PostMapping
    @PreAuthorize("hasPermission('PERMISSION', 'CREATE')")
    @Operation(summary = "Tạo mới quyền")
    public ApiResponse<PermissionResponse> createPermission(@Valid @RequestBody PermissionRequest request) {
        return ApiResponse.ok("Tạo quyền thành công", permissionService.createPermission(request));
    }

    @PutMapping("/{id}")
    @PreAuthorize("hasPermission('PERMISSION', 'UPDATE')")
    @Operation(summary = "Cập nhật thông tin quyền")
    public ApiResponse<PermissionResponse> updatePermission(
            @PathVariable Long id,
            @Valid @RequestBody PermissionRequest request) {
        return ApiResponse.ok("Cập nhật quyền thành công", permissionService.updatePermission(id, request));
    }

    @DeleteMapping("/{id}")
    @PreAuthorize("hasPermission('PERMISSION', 'DELETE')")
    @Operation(summary = "Xóa mềm quyền")
    public ApiResponse<Void> deletePermission(@PathVariable Long id) {
        permissionService.deletePermission(id);
        return ApiResponse.ok("Xóa mềm quyền thành công", null);
    }
}
