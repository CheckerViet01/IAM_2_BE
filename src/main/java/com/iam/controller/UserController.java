package com.iam.controller;

import com.iam.dto.request.AssignRolesRequest;
import com.iam.dto.request.ChangePasswordRequest;
import com.iam.dto.request.ResetPasswordRequest;
import com.iam.dto.request.UserCreateRequest;
import com.iam.dto.request.UserUpdateRequest;
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

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.time.LocalDateTime;
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
    private final com.iam.repository.AvatarRepository avatarRepository;
    private final com.iam.repository.PasswordResetTokenRepository passwordResetTokenRepository;
    private final com.iam.service.EmailService emailService;
    private final org.springframework.security.crypto.password.PasswordEncoder passwordEncoder;
    private final com.iam.service.KeycloakAdminService keycloakAdminService;

    private User resolveUser(Authentication authentication) {
        if (authentication == null) {
            throw new AppException(ErrorCode.UNAUTHENTICATED);
        }
        String principal = authentication.getName();
        String username = null;
        String email = null;
        if (authentication.getPrincipal() instanceof org.springframework.security.oauth2.jwt.Jwt jwt) {
            if (jwt.hasClaim("preferred_username")) {
                username = jwt.getClaimAsString("preferred_username");
            }
            if (jwt.hasClaim("email")) {
                email = jwt.getClaimAsString("email");
            }
        }
        final String uName = username;
        final String uEmail = email;

        return userRepository.findByUsername(principal)
                .or(() -> userRepository.findByEmail(principal))
                .or(() -> userRepository.findByKeycloakId(principal))
                .or(() -> uName != null ? userRepository.findByUsername(uName) : java.util.Optional.empty())
                .or(() -> uEmail != null ? userRepository.findByEmail(uEmail) : java.util.Optional.empty())
                .orElseThrow(() -> new AppException(ErrorCode.USER_NOT_FOUND));
    }

    @GetMapping("/profile")
    @Operation(summary = "Lấy thông tin tài khoản đang đăng nhập")
    public ApiResponse<Map<String, Object>> getProfile(Authentication authentication) {
        User user = resolveUser(authentication);

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
        profile.put("twoFactorEnabled", user.isTwoFactorEnabled());
        profile.put("twoFactorMethod", "EMAIL");
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
        User user = resolveUser(authentication);
        userService.changePassword(user.getUsername(), request);
        return ApiResponse.ok("Đổi mật khẩu thành công", null);
    }

    @PutMapping("/profile")
    @Operation(summary = "Cập nhật hồ sơ tài khoản hiện tại")
    public ApiResponse<Map<String, Object>> updateProfile(
            Authentication authentication,
            @RequestBody Map<String, Object> body) {
        User user = resolveUser(authentication);

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
    @org.springframework.transaction.annotation.Transactional
    public ApiResponse<Map<String, Object>> uploadAvatar(
            Authentication authentication,
            @RequestParam(value = "file", required = true) org.springframework.web.multipart.MultipartFile file) {
        if (file == null || file.isEmpty()) {
            throw new AppException(ErrorCode.INVALID_REQUEST, "Tệp ảnh không hợp lệ hoặc rỗng");
        }
        User user = resolveUser(authentication);

        try {
            Path uploadDir = Paths.get("uploads", "avatars");
            if (!Files.exists(uploadDir)) {
                Files.createDirectories(uploadDir);
            }

            String originalName = file.getOriginalFilename() != null ? file.getOriginalFilename() : "avatar.png";
            String cleanName = originalName.replaceAll("[^a-zA-Z0-9.-]", "_");
            String storedFileName = "u" + user.getId() + "_" + System.currentTimeMillis() + "_" + cleanName;
            Path targetPath = uploadDir.resolve(storedFileName);

            Files.copy(file.getInputStream(), targetPath, StandardCopyOption.REPLACE_EXISTING);

            String avatarUrl = "/uploads/avatars/" + storedFileName;

            // Đặt các avatar cũ thành current = false
            avatarRepository.resetCurrentAvatars(user.getId());

            // Lưu avatar mới vào bảng avatars
            com.iam.entity.Avatar avatar = com.iam.entity.Avatar.builder()
                    .userId(user.getId())
                    .fileName(storedFileName)
                    .originalFileName(originalName)
                    .fileUrl(avatarUrl)
                    .fileSizeBytes(file.getSize())
                    .current(true)
                    .uploadedAt(LocalDateTime.now())
                    .deleted(false)
                    .build();
            avatarRepository.save(avatar);

            // Cập nhật URL vào user
            user.setAvatarUrl(avatarUrl);
            userRepository.save(user);

            return ApiResponse.ok("Tải ảnh đại diện thành công", Map.of("avatarUrl", avatarUrl));
        } catch (IOException e) {
            throw new AppException(ErrorCode.INTERNAL_SERVER_ERROR, "Lỗi khi lưu tệp ảnh: " + e.getMessage());
        }
    }

    @GetMapping("/avatars")
    @Operation(summary = "Lấy danh sách lịch sử avatar")
    public ApiResponse<List<Map<String, Object>>> getAvatars(Authentication authentication) {
        User user = resolveUser(authentication);

        List<com.iam.entity.Avatar> avatars = avatarRepository.findByUserIdAndDeletedFalseOrderByUploadedAtDesc(user.getId());
        List<Map<String, Object>> result = avatars.stream().map(av -> {
            Map<String, Object> item = new HashMap<>();
            item.put("id", av.getId());
            item.put("fileName", av.getFileName());
            item.put("originalFileName", av.getOriginalFileName());
            item.put("fileUrl", av.getFileUrl());
            item.put("fileSizeBytes", av.getFileSizeBytes());
            item.put("isCurrent", av.isCurrent());
            item.put("uploadedAt", av.getUploadedAt());
            return item;
        }).collect(Collectors.toList());

        return ApiResponse.ok(result);
    }

    @PostMapping("/2fa/request-enable")
    @Operation(summary = "Yêu cầu kích hoạt 2FA")
    @org.springframework.transaction.annotation.Transactional
    public ApiResponse<String> requestEnable2fa(Authentication authentication) {
        User user = resolveUser(authentication);

        String otp = String.format("%06d", new java.util.Random().nextInt(1000000));
        String tokenStr = "2FA_ENABLE:" + user.getId() + ":" + otp;

        com.iam.entity.PasswordResetToken token = com.iam.entity.PasswordResetToken.builder()
                .userId(user.getId())
                .token(tokenStr)
                .expiresAt(LocalDateTime.now().plusMinutes(5))
                .used(false)
                .build();
        passwordResetTokenRepository.save(token);

        emailService.sendOtpEmail(
                user.getEmail(),
                otp,
                "Mã OTP Kích Hoạt Bảo Mật 2FA - IAM Verse",
                "Kích Hoạt Bảo Vệ 2 Bước (2FA)",
                "Bạn đang yêu cầu kích hoạt lá chắn bảo mật xác thực 2 bước (2FA) qua Email cho tài khoản <strong>" + user.getEmail() + "</strong>."
        );

        return ApiResponse.ok("Mã OTP kích hoạt 2FA đã được gửi về email " + user.getEmail(), otp);
    }

    @PostMapping("/2fa/confirm-enable")
    @Operation(summary = "Xác nhận kích hoạt 2FA")
    @org.springframework.transaction.annotation.Transactional
    public ApiResponse<String> confirmEnable2fa(Authentication authentication, @RequestBody Map<String, Object> body) {
        String otpCode = body != null ? (String) body.get("otpCode") : null;
        if (otpCode == null || otpCode.trim().length() != 6) {
            throw new AppException(ErrorCode.INVALID_REQUEST, "Mã OTP phải gồm 6 chữ số");
        }

        User user = resolveUser(authentication);

        String expectedToken = "2FA_ENABLE:" + user.getId() + ":" + otpCode.trim();
        com.iam.entity.PasswordResetToken token = passwordResetTokenRepository.findByTokenAndUsedFalse(expectedToken)
                .orElseThrow(() -> new AppException(ErrorCode.INVALID_REQUEST, "Mã OTP không chính xác hoặc đã hết hạn!"));

        if (token.getExpiresAt().isBefore(LocalDateTime.now())) {
            throw new AppException(ErrorCode.INVALID_REQUEST, "Mã OTP đã hết hạn, vui lòng yêu cầu mã mới!");
        }

        token.setUsed(true);
        passwordResetTokenRepository.save(token);

        user.setTwoFactorEnabled(true);
        userRepository.save(user);

        return ApiResponse.ok("Kích hoạt 2FA thành công! Lá chắn bảo vệ đã được bật 🛡️", "SUCCESS");
    }

    @PostMapping("/2fa/disable")
    @Operation(summary = "Tắt 2FA")
    @org.springframework.transaction.annotation.Transactional
    public ApiResponse<String> disable2fa(Authentication authentication, @RequestBody Map<String, Object> body) {
        String password = body != null ? (String) body.get("password") : null;
        if (password == null || password.isBlank()) {
            throw new AppException(ErrorCode.INVALID_REQUEST, "Vui lòng nhập mật khẩu xác nhận");
        }

        User user = resolveUser(authentication);

        boolean authenticated = false;
        if (user.getPasswordHash() != null && !user.getPasswordHash().isBlank()) {
            if (passwordEncoder.matches(password, user.getPasswordHash())) {
                authenticated = true;
            }
        }
        if (!authenticated) {
            try {
                String loginIdentifier = user.getUsername() != null ? user.getUsername() : user.getEmail();
                keycloakAdminService.loginDirect(loginIdentifier, password);
                authenticated = true;
            } catch (Exception ex) {
                if (user.getEmail() != null && !user.getEmail().equalsIgnoreCase(user.getUsername())) {
                    try {
                        keycloakAdminService.loginDirect(user.getEmail(), password);
                        authenticated = true;
                    } catch (Exception ignored) {}
                }
            }
        }

        if (!authenticated) {
            throw new AppException(ErrorCode.INVALID_CREDENTIALS, "Mật khẩu xác nhận không chính xác!");
        }

        user.setTwoFactorEnabled(false);
        userRepository.save(user);

        return ApiResponse.ok("Đã tắt bảo vệ 2FA thành công.", "SUCCESS");
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
