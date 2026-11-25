package com.iam.config;

import com.iam.entity.Role;
import com.iam.entity.User;
import com.iam.repository.RoleRepository;
import com.iam.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;

/**
 * Khởi tạo dữ liệu người dùng ban đầu theo yêu cầu đề bài mục 9:
 * - Tạo tài khoản Quản trị hệ thống (SYSTEM_ADMIN)
 * - Tự động đồng bộ tài khoản test có sẵn từ Keycloak vào DB IAM
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class DataInitializer implements CommandLineRunner {

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;

    @Override
    @Transactional
    public void run(String... args) {
        log.info("Checking initial system administrator data...");

        // Lấy danh sách Roles hệ thống
        List<Role> systemRoles = roleRepository.findByCodeIn(List.of("SYSTEM_ADMIN", "USER_MANAGER"));
        Set<Role> adminRoles = new HashSet<>(systemRoles);

        // 1. Tạo tài khoản admin mặc định cho Self-IDP nếu chưa có
        if (!userRepository.existsByUsername("admin")) {
            User admin = User.builder()
                    .username("admin")
                    .email("admin@iam.com")
                    .passwordHash(passwordEncoder.encode("Admin@123"))
                    .fullName("Quản trị viên Hệ thống")
                    .phoneNumber("0988888888")
                    .authProvider("LOCAL")
                    .locked(false)
                    .enabled(true)
                    .roles(adminRoles)
                    .build();

            userRepository.save(admin);
            log.info("Initialized default Self-IDP admin account: username='admin', password='Admin@123'");
        }

        // 2. Đồng bộ user test có sẵn trên Keycloak ("testuser2026@gmail.com") vào DB IAM
        Optional<User> keycloakUser = userRepository.findByUsername("testuser2026@gmail.com");
        if (keycloakUser.isEmpty()) {
            User syncUser = User.builder()
                    .username("testuser2026@gmail.com")
                    .email("testuser2026@gmail.com")
                    .fullName("Keycloak Test User")
                    .keycloakId("ed66b86e-584c-4515-b918-fd6983610209")
                    .authProvider("KEYCLOAK")
                    .locked(false)
                    .enabled(true)
                    .roles(adminRoles)
                    .build();

            userRepository.save(syncUser);
            log.info("Synchronized existing Keycloak user 'testuser2026@gmail.com' into IAM database with SYSTEM_ADMIN role");
        }
    }
}
