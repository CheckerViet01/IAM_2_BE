package com.iam.controller;

import com.iam.dto.request.*;
import com.iam.dto.response.ApiResponse;
import com.iam.dto.response.PageResponse;
import com.iam.dto.response.UserResponse;
import com.iam.service.UserService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Pageable;
import org.springframework.data.web.PageableDefault;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/users")
@RequiredArgsConstructor
@Tag(name = "Quản lý Người dùng (Users)", description = "Các API Quản lý tài khoản người dùng, phân quyền, khóa và reset mật khẩu")
public class UserController {

    private final UserService userService;

    @GetMapping
    @PreAuthorize("hasPermission('USER', 'READ')")
    @Operation(summary = "Xem danh sách người dùng (hỗ trợ tìm kiếm theo từ khóa và phân trang)")
    public ApiResponse<PageResponse<UserResponse>> getUsers(
            @RequestParam(required = false) String keyword,
            @PageableDefault(size = 10) Pageable pageable) {
        return ApiResponse.ok(userService.getUsers(keyword, pageable));
    }

    @GetMapping("/{id}")
    @PreAuthorize("hasPermission('USER', 'READ')")
    @Operation(summary = "Xem thông tin chi tiết của người dùng")
    public ApiResponse<UserResponse> getUserById(@PathVariable Long id) {
        return ApiResponse.ok(userService.getUserById(id));
    }

    @PostMapping
    @PreAuthorize("hasPermission('USER', 'CREATE')")
    @Operation(summary = "Tạo mới người dùng (Tự động đồng bộ sang Keycloak nếu bật Keycloak)")
    public ApiResponse<UserResponse> createUser(@Valid @RequestBody UserCreateRequest request) {
        return ApiResponse.ok("Tạo người dùng thành công", userService.createUser(request));
    }

    @PutMapping("/{id}")
    @PreAuthorize("hasPermission('USER', 'UPDATE')")
    @Operation(summary = "Cập nhật thông tin người dùng")
    public ApiResponse<UserResponse> updateUser(
            @PathVariable Long id,
            @Valid @RequestBody UserUpdateRequest request) {
        return ApiResponse.ok("Cập nhật thông tin thành công", userService.updateUser(id, request));
    }

    @DeleteMapping("/{id}")
    @PreAuthorize("hasPermission('USER', 'DELETE')")
    @Operation(summary = "Xóa mềm người dùng (Sử dụng trường deleted)")
    public ApiResponse<Void> deleteUser(@PathVariable Long id) {
        userService.deleteUser(id);
        return ApiResponse.ok("Xóa mềm người dùng thành công", null);
    }

    @PatchMapping("/{id}/lock")
    @PreAuthorize("hasPermission('USER', 'LOCK')")
    @Operation(summary = "Khóa hoặc Mở khóa tài khoản người dùng (Đồng bộ sang Keycloak)")
    public ApiResponse<UserResponse> lockUser(
            @PathVariable Long id,
            @RequestParam boolean locked) {
        String msg = locked ? "Khóa tài khoản thành công" : "Mở khóa tài khoản thành công";
        return ApiResponse.ok(msg, userService.lockUser(id, locked));
    }

    @PostMapping("/{id}/reset-password")
    @PreAuthorize("hasPermission('USER', 'RESET_PASSWORD')")
    @Operation(summary = "Reset mật khẩu cho người dùng (Đồng bộ sang Keycloak)")
    public ApiResponse<Void> resetPassword(
            @PathVariable Long id,
            @Valid @RequestBody ResetPasswordRequest request) {
        userService.resetPassword(id, request);
        return ApiResponse.ok("Đặt lại mật khẩu thành công", null);
    }

    @PostMapping("/{id}/roles")
    @PreAuthorize("hasPermission('USER', 'ASSIGN_ROLE')")
    @Operation(summary = "Gán vai trò cho người dùng")
    public ApiResponse<UserResponse> assignRoles(
            @PathVariable Long id,
            @Valid @RequestBody AssignRolesRequest request) {
        return ApiResponse.ok("Gán vai trò cho người dùng thành công", userService.assignRoles(id, request));
    }

    @PostMapping("/change-password")
    @Operation(summary = "User tự đổi mật khẩu (Tính năng nâng cao - Hỗ trợ cả Keycloak và Self-IDP)")
    public ApiResponse<Void> changePassword(
            Authentication authentication,
            @Valid @RequestBody ChangePasswordRequest request) {
        userService.changePassword(authentication.getName(), request);
        return ApiResponse.ok("Đổi mật khẩu thành công", null);
    }
}
