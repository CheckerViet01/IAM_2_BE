package com.iam.service;

import com.iam.dto.request.*;
import com.iam.dto.response.PageResponse;
import com.iam.dto.response.RoleResponse;
import com.iam.dto.response.UserResponse;
import com.iam.entity.Role;
import com.iam.entity.User;
import com.iam.exception.AppException;
import com.iam.exception.ErrorCode;
import com.iam.repository.RoleRepository;
import com.iam.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
@Slf4j
public class UserService {

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final RoleService roleService;
    private final KeycloakAdminService keycloakAdminService;
    private final PasswordEncoder passwordEncoder;

    @Value("${app.idp.provider:keycloak}")
    private String idpProvider;

    public PageResponse<UserResponse> getUsers(String keyword, Pageable pageable) {
        Page<User> page = userRepository.searchUsers(keyword, pageable);
        return PageResponse.from(page.map(this::mapToResponse));
    }

    public UserResponse getUserById(Long id) {
        User user = userRepository.findById(id)
                .orElseThrow(() -> new AppException(ErrorCode.USER_NOT_FOUND));
        return mapToResponse(user);
    }

    @Transactional
    public UserResponse createUser(UserCreateRequest request) {
        String effectiveUsername = request.getEffectiveUsername();
        if (userRepository.existsByUsername(effectiveUsername) || userRepository.existsByEmail(request.getEmail())) {
            throw new AppException(ErrorCode.USER_EXISTED);
        }

        String keycloakId = null;
        String authProvider = "LOCAL";

        // Nếu bật chế độ Keycloak: Tạo tài khoản trên Keycloak trước để đồng bộ
        if ("keycloak".equalsIgnoreCase(idpProvider)) {
            keycloakId = keycloakAdminService.createUser(
                    effectiveUsername,
                    request.getEmail().trim(),
                    request.getPassword(),
                    request.getFullName()
            );
            authProvider = "KEYCLOAK";
        }

        // Lấy danh sách Roles
        Set<Role> roles = new HashSet<>();
        Set<String> inputRoles = request.getEffectiveRoleCodes();
        if (inputRoles != null && !inputRoles.isEmpty()) {
            Set<String> normalized = new HashSet<>(inputRoles);
            if (inputRoles.contains("ROLE_USER")) normalized.add("USER");
            if (inputRoles.contains("USER")) normalized.add("ROLE_USER");
            List<Role> roleList = roleRepository.findByCodeIn(normalized);
            roles.addAll(roleList);
        }
        if (roles.isEmpty()) {
            roleRepository.findByCode("USER").ifPresent(roles::add);
        }

        User user = User.builder()
                .username(effectiveUsername)
                .email(request.getEmail().trim())
                .passwordHash(request.getPassword() != null ? passwordEncoder.encode(request.getPassword()) : null)
                .fullName(request.getFullName())
                .phoneNumber(request.getPhoneNumber())
                .keycloakId(keycloakId)
                .authProvider(authProvider)
                .locked(false)
                .enabled(true)
                .roles(roles)
                .build();

        User saved = userRepository.save(user);
        log.info("Created user: id={}, username={}, authProvider={}", saved.getId(), saved.getUsername(), authProvider);
        return mapToResponse(saved);
    }

    @Transactional
    public UserResponse updateUser(Long id, UserUpdateRequest request) {
        User user = userRepository.findById(id)
                .orElseThrow(() -> new AppException(ErrorCode.USER_NOT_FOUND));

        if (request.getFullName() != null) user.setFullName(request.getFullName().trim());
        if (request.getPhoneNumber() != null) user.setPhoneNumber(request.getPhoneNumber().trim());
        if (request.getAvatarUrl() != null) user.setAvatarUrl(request.getAvatarUrl().trim());

        User updated = userRepository.save(user);
        log.info("Updated user: id={}, username={}", id, updated.getUsername());
        return mapToResponse(updated);
    }

    @Transactional
    public void deleteUser(Long id) {
        User user = userRepository.findById(id)
                .orElseThrow(() -> new AppException(ErrorCode.USER_NOT_FOUND));

        if ("admin".equalsIgnoreCase(user.getUsername())) {
            throw new AppException(ErrorCode.UNAUTHORIZED, "Không thể xóa tài khoản Quản trị viên tối cao (admin)!");
        }

        // Xóa mềm trong DB nội bộ của IAM
        userRepository.delete(user);

        // Đồng bộ xóa/vô hiệu hóa trên Keycloak nếu có keycloakId
        if (user.getKeycloakId() != null && !user.getKeycloakId().isBlank()) {
            keycloakAdminService.deleteUser(user.getKeycloakId());
        }

        log.info("Soft-deleted user: id={}, username={}", id, user.getUsername());
    }

    @Transactional
    public UserResponse lockUser(Long id, boolean locked) {
        User user = userRepository.findById(id)
                .orElseThrow(() -> new AppException(ErrorCode.USER_NOT_FOUND));

        if ("admin".equalsIgnoreCase(user.getUsername()) && locked) {
            throw new AppException(ErrorCode.UNAUTHORIZED, "Không thể khóa tài khoản Quản trị viên tối cao (admin)!");
        }

        user.setLocked(locked);
        User saved = userRepository.save(user);

        // Đồng bộ trạng thái khóa sang Keycloak
        if (user.getKeycloakId() != null && !user.getKeycloakId().isBlank()) {
            keycloakAdminService.lockUser(user.getKeycloakId(), locked);
        }

        log.info("User id={} locked status updated to: {}", id, locked);
        return mapToResponse(saved);
    }

    @Transactional
    public void resetPassword(Long id, ResetPasswordRequest request) {
        User user = userRepository.findById(id)
                .orElseThrow(() -> new AppException(ErrorCode.USER_NOT_FOUND));

        // Cập nhật mật khẩu mã hóa trong DB nội bộ
        user.setPasswordHash(passwordEncoder.encode(request.getNewPassword()));
        userRepository.save(user);

        // Đồng bộ reset mật khẩu sang Keycloak
        if (user.getKeycloakId() != null && !user.getKeycloakId().isBlank()) {
            keycloakAdminService.resetPassword(user.getKeycloakId(), request.getNewPassword());
        }

        log.info("Reset password for user id={}, username={}", id, user.getUsername());
    }

    @Transactional
    public UserResponse assignRoles(Long id, AssignRolesRequest request) {
        User user = userRepository.findById(id)
                .orElseThrow(() -> new AppException(ErrorCode.USER_NOT_FOUND));

        List<Role> roles = roleRepository.findByCodeIn(request.getRoleCodes());
        user.setRoles(new HashSet<>(roles));

        User saved = userRepository.save(user);
        log.info("Assigned {} roles to user id={}", roles.size(), id);
        return mapToResponse(saved);
    }

    @Transactional
    public void changePassword(String currentUsername, ChangePasswordRequest request) {
        User user = userRepository.findByUsername(currentUsername)
                .or(() -> userRepository.findByEmail(currentUsername))
                .orElseThrow(() -> new AppException(ErrorCode.USER_NOT_FOUND));

        // Nếu ở chế độ Self-IDP có mật khẩu lưu DB, kiểm tra mật khẩu cũ
        if (user.getPasswordHash() != null && !user.getPasswordHash().isBlank()) {
            if (!passwordEncoder.matches(request.getOldPassword(), user.getPasswordHash())) {
                throw new AppException(ErrorCode.INVALID_CREDENTIALS, "Mật khẩu cũ không chính xác");
            }
            user.setPasswordHash(passwordEncoder.encode(request.getNewPassword()));
            userRepository.save(user);
        }

        // Nếu có tài khoản Keycloak, đồng bộ đổi mật khẩu trên Keycloak
        if (user.getKeycloakId() != null && !user.getKeycloakId().isBlank()) {
            keycloakAdminService.resetPassword(user.getKeycloakId(), request.getNewPassword());
        }

        log.info("User '{}' changed password successfully", currentUsername);
    }

    public UserResponse mapToResponse(User user) {
        Set<RoleResponse> roleResponses = user.getRoles() != null
                ? user.getRoles().stream().map(roleService::mapToResponse).collect(Collectors.toSet())
                : Set.of();

        return UserResponse.builder()
                .id(user.getId())
                .username(user.getUsername())
                .email(user.getEmail())
                .fullName(user.getFullName())
                .phoneNumber(user.getPhoneNumber())
                .avatarUrl(user.getAvatarUrl())
                .keycloakId(user.getKeycloakId())
                .authProvider(user.getAuthProvider())
                .locked(user.isLocked())
                .enabled(user.isEnabled())
                .lastLoginAt(user.getLastLoginAt())
                .roles(roleResponses)
                .createdAt(user.getCreatedAt())
                .createdBy(user.getCreatedBy())
                .updatedAt(user.getUpdatedAt())
                .updatedBy(user.getUpdatedBy())
                .build();
    }
}
