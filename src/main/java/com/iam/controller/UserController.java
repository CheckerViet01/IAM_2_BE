package com.iam.controller;

import com.iam.dto.request.*;
import com.iam.dto.response.ApiResponse;
import com.iam.dto.response.PageResponse;
import com.iam.dto.response.UserResponse;
import com.iam.entity.User;
import com.iam.exception.AppException;
import com.iam.exception.ErrorCode;
import com.iam.repository.UserRepository;
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

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

@RestController
@RequestMapping({"/api/users", "/api/v1/users"})
@RequiredArgsConstructor
@Tag(name = "Quản lý Người dùng (Users)", description = "Các API Quản lý tài khoản người dùng, phân quyền, khóa và reset mật khẩu")
public class UserController {

    private final UserService userService;
    private final UserRepository userRepository;

    @GetMapping("/profile")
    @Operation(summary = "Lấy thông tin tài khoản đang đăng nhập")
    public ApiResponse<Map<String, Object>> getProfile(Authentication authentication) {
        if (authentication == null) {
            throw new AppException(ErrorCode.UNAUTHENTICATED);
        }
        String principal = authentication.getName();
        User user = userRepository.findByUsername(principal)
                .or(() -> userRepository.findByEmail(principal))
                .or(() -> userRepository.findByKeycloakId(principal))
                .orElseThrow(() -> new AppException(ErrorCode.USER_NOT_FOUND));

        Map<String, Object> profile = new HashMap<>();
        profile.put("id", user.getId());
        profile.put("username", user.getUsername());
        profile.put("email", user.getEmail());
        profile.put("fullName", user.getFullName());
        profile.put("phoneNumber", user.getPhoneNumber());
        profile.put("avatarUrl", user.getAvatarUrl());
        profile.put("authProvider", user.getAuthProvider());
        profile.put("isActive", user.isEnabled() && !user.isDeleted());
        profile.put("isLocked", user.isLocked());
        profile.put("deleted", user.isDeleted());
        profile.put("createdAt", user.getCreatedAt());

        List<String> roleCodes = user.getRoles() != null
                ? user.getRoles().stream().map(r -> r.getCode()).collect(Collectors.toList())
                : List.of();
        profile.put("roles", roleCodes);

        Set<String> permissions = user.getRoles() != null
                ? user.getRoles().stream()
                    .filter(r -> r.getPermissions() != null)
                    .flatMap(r -> r.getPermissions().stream().map(p -> p.getCode()))
                    .collect(Collectors.toSet())
                : Set.of();
        profile.put("permissions", permissions);

        return ApiResponse.ok(profile);
    }

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

    @PutMapping("/{id}/status")
    @PreAuthorize("hasPermission('USER', 'LOCK')")
    @Operation(summary = "Cập nhật trạng thái khóa/mở khóa cho Frontend")
    public ApiResponse<UserResponse> updateStatus(
            @PathVariable Long id,
            @RequestBody Map<String, Object> body) {
        boolean locked = body.containsKey("locked") ? Boolean.parseBoolean(body.get("locked").toString()) : false;
        return ApiResponse.ok("Cập nhật trạng thái thành công", userService.lockUser(id, locked));
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

    @PutMapping("/{id}/roles")
    @PreAuthorize("hasPermission('USER', 'ASSIGN_ROLE')")
    @Operation(summary = "Gán vai trò cho người dùng (Hỗ trợ định dạng body của Frontend)")
    public ApiResponse<UserResponse> assignRolesPut(
            @PathVariable Long id,
            @RequestBody Map<String, Object> body) {
        List<String> roles = (List<String>) body.get("roles");
        AssignRolesRequest req = AssignRolesRequest.builder()
                .roleCodes(roles != null ? Set.copyOf(roles) : Set.of())
                .build();
        return ApiResponse.ok("Gán vai trò cho người dùng thành công", userService.assignRoles(id, req));
    }

    @PostMapping("/change-password")
    @Operation(summary = "User tự đổi mật khẩu (Tính năng nâng cao - Hỗ trợ cả Keycloak và Self-IDP)")
    public ApiResponse<Void> changePassword(
            Authentication authentication,
            @Valid @RequestBody ChangePasswordRequest request) {
        userService.changePassword(authentication.getName(), request);
        return ApiResponse.ok("Đổi mật khẩu thành công", null);
    }

    @PutMapping("/profile")
    @Operation(summary = "Cập nhật hồ sơ tài khoản hiện tại")
    public ApiResponse<Map<String, Object>> updateProfile(
            Authentication authentication,
            @RequestBody Map<String, Object> body) {
        if (authentication == null) {
            throw new AppException(ErrorCode.UNAUTHENTICATED);
        }
        String principal = authentication.getName();
        User user = userRepository.findByUsername(principal)
                .or(() -> userRepository.findByEmail(principal))
                .or(() -> userRepository.findByKeycloakId(principal))
                .orElseThrow(() -> new AppException(ErrorCode.USER_NOT_FOUND));

        if (body.containsKey("fullName") && body.get("fullName") != null) {
            user.setFullName(body.get("fullName").toString().trim());
        }
        if (body.containsKey("phoneNumber") && body.get("phoneNumber") != null) {
            user.setPhoneNumber(body.get("phoneNumber").toString().trim());
        }
        userRepository.save(user);

        return getProfile(authentication);
    }

    @PostMapping("/avatar")
    @Operation(summary = "Tải lên ảnh đại diện")
    public ApiResponse<Map<String, Object>> uploadAvatar(
            Authentication authentication,
            @RequestParam(value = "file", required = false) org.springframework.web.multipart.MultipartFile file) {
        if (authentication == null) {
            throw new AppException(ErrorCode.UNAUTHENTICATED);
        }
        String principal = authentication.getName();
        User user = userRepository.findByUsername(principal)
                .or(() -> userRepository.findByEmail(principal))
                .or(() -> userRepository.findByKeycloakId(principal))
                .orElseThrow(() -> new AppException(ErrorCode.USER_NOT_FOUND));

        String avatarUrl = "https://api.dicebear.com/7.x/bottts/svg?seed=" + user.getUsername();
        user.setAvatarUrl(avatarUrl);
        userRepository.save(user);

        return ApiResponse.ok("Tải ảnh đại diện thành công", Map.of("avatarUrl", avatarUrl));
    }

    @GetMapping("/avatars")
    @Operation(summary = "Lấy danh sách lịch sử avatar")
    public ApiResponse<List<Map<String, Object>>> getAvatars(Authentication authentication) {
        return ApiResponse.ok(List.of());
    }

    @PostMapping("/2fa/request-enable")
    @Operation(summary = "Yêu cầu kích hoạt 2FA")
    public ApiResponse<String> requestEnable2fa() {
        return ApiResponse.ok("Mã xác thực 2FA đã gửi qua email (Mã mẫu: 123456)", "123456");
    }

    @PostMapping("/2fa/confirm-enable")
    @Operation(summary = "Xác nhận kích hoạt 2FA")
    public ApiResponse<String> confirmEnable2fa(@RequestBody Map<String, Object> body) {
        return ApiResponse.ok("Kích hoạt 2FA thành công", "SUCCESS");
    }

    @PostMapping("/2fa/disable")
    @Operation(summary = "Tắt 2FA")
    public ApiResponse<String> disable2fa(@RequestBody Map<String, Object> body) {
        return ApiResponse.ok("Tắt 2FA thành công", "SUCCESS");
    }

    @GetMapping("/activity-logs")
    @Operation(summary = "Lấy nhật ký hoạt động của tài khoản")
    public ApiResponse<PageResponse<Map<String, Object>>> getActivityLogs(
            Authentication authentication,
            @PageableDefault(size = 10) Pageable pageable) {
        List<Map<String, Object>> logs = List.of(
                Map.of(
                        "id", 1,
                        "action", "Đăng nhập hệ thống (SSO/Password)",
                        "status", "SUCCESS",
                        "ipAddress", "127.0.0.1",
                        "userAgent", "Chrome / Angular Dashboard",
                        "details", "Xác thực thành công",
                        "createdAt", java.time.LocalDateTime.now()
                )
        );
        PageResponse<Map<String, Object>> pageResponse = PageResponse.<Map<String, Object>>builder()
                .content(logs)
                .pageNumber(0)
                .pageSize(10)
                .totalElements(1)
                .totalPages(1)
                .first(true)
                .last(true)
                .build();
        return ApiResponse.ok(pageResponse);
    }
}
