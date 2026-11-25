package com.iam.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.iam.dto.response.ApiResponse;
import com.iam.entity.Permission;
import com.iam.entity.Role;
import com.iam.entity.User;
import com.iam.repository.UserRepository;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.HashSet;
import java.util.Optional;
import java.util.Set;

/**
 * Filter đáp ứng yêu cầu cốt lõi đề bài mục 1:
 * "Dùng Bearer access token đó gắn vào các request, mỗi request kiểm tra thông tin user trong database của iam,
 * nếu database của iam có thì mới cho thực hiện request."
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class UserExistenceFilter extends OncePerRequestFilter {

    private final UserRepository userRepository;
    private final ObjectMapper objectMapper = new ObjectMapper();

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        // Chỉ kiểm tra khi request đã được decode token và xác thực danh tính
        if (authentication != null && authentication.isAuthenticated() && !"anonymousUser".equals(authentication.getPrincipal())) {
            String principalIdentifier = null;

            // Nếu là OAuth2 Jwt từ Keycloak
            if (authentication.getPrincipal() instanceof Jwt jwt) {
                // Keycloak chứa username trong claim "preferred_username" hoặc email hoặc sub
                if (jwt.hasClaim("preferred_username")) {
                    principalIdentifier = jwt.getClaimAsString("preferred_username");
                } else if (jwt.hasClaim("email")) {
                    principalIdentifier = jwt.getClaimAsString("email");
                } else {
                    principalIdentifier = jwt.getSubject();
                }
            } else {
                principalIdentifier = authentication.getName();
            }

            if (principalIdentifier != null) {
                Optional<User> userOpt = userRepository.findByUsername(principalIdentifier);
                if (userOpt.isEmpty()) {
                    userOpt = userRepository.findByEmail(principalIdentifier);
                }
                if (userOpt.isEmpty()) {
                    userOpt = userRepository.findByKeycloakId(principalIdentifier);
                }

                // 1. Kiểm tra tồn tại trong DB IAM
                if (userOpt.isEmpty()) {
                    log.warn("Blocked request: User '{}' does NOT exist in IAM database!", principalIdentifier);
                    sendErrorResponse(response, HttpStatus.UNAUTHORIZED, "Tài khoản không tồn tại trong cơ sở dữ liệu IAM Service");
                    return;
                }

                User user = userOpt.get();

                // 2. Kiểm tra tài khoản có bị khóa không
                if (user.isLocked()) {
                    log.warn("Blocked request: User '{}' is locked in IAM database!", principalIdentifier);
                    sendErrorResponse(response, HttpStatus.FORBIDDEN, "Tài khoản đã bị khóa trong hệ thống IAM Service");
                    return;
                }

                // 3. Kiểm tra tài khoản có bị xóa mềm không
                if (user.isDeleted() || !user.isEnabled()) {
                    log.warn("Blocked request: User '{}' is deleted or disabled!", principalIdentifier);
                    sendErrorResponse(response, HttpStatus.FORBIDDEN, "Tài khoản đã bị vô hiệu hóa hoặc bị xóa");
                    return;
                }

                // 4. Bổ sung quyền từ Database IAM vào Authentication để áp dụng RBAC chuẩn xác
                Set<GrantedAuthority> authorities = new HashSet<>();
                if (user.getRoles() != null) {
                    for (Role role : user.getRoles()) {
                        authorities.add(new SimpleGrantedAuthority("ROLE_" + role.getCode()));
                        authorities.add(new SimpleGrantedAuthority(role.getCode()));
                        if (role.getPermissions() != null) {
                            for (Permission permission : role.getPermissions()) {
                                authorities.add(new SimpleGrantedAuthority(permission.getCode()));
                            }
                        }
                    }
                }

                // Cập nhật Authentication với danh sách quyền lấy từ IAM DB
                UsernamePasswordAuthenticationToken enrichedAuth = new UsernamePasswordAuthenticationToken(
                        user.getUsername(),
                        authentication.getCredentials() != null ? authentication.getCredentials() : "N/A",
                        authorities
                );
                enrichedAuth.setDetails(authentication.getDetails());
                SecurityContextHolder.getContext().setAuthentication(enrichedAuth);
            }
        }

        filterChain.doFilter(request, response);
    }

    private void sendErrorResponse(HttpServletResponse response, HttpStatus status, String message) throws IOException {
        response.setStatus(status.value());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setCharacterEncoding("UTF-8");

        ApiResponse<Object> apiResponse = ApiResponse.error(message);
        response.getWriter().write(objectMapper.writeValueAsString(apiResponse));
    }
}
