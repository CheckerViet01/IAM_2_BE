package com.iam.service;

import com.iam.dto.response.TokenResponse;
import com.iam.exception.AppException;
import com.iam.exception.ErrorCode;
import jakarta.ws.rs.core.Response;
import lombok.extern.slf4j.Slf4j;
import org.keycloak.OAuth2Constants;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.KeycloakBuilder;
import org.keycloak.admin.client.resource.RealmResource;
import org.keycloak.admin.client.resource.UsersResource;
import org.keycloak.representations.idm.CredentialRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

import java.util.Collections;
import java.util.List;
import java.util.Map;

@Service
@Slf4j
public class KeycloakAdminService {

    @Value("${app.keycloak.auth-server-url:http://localhost:8180}")
    private String authServerUrl;

    @Value("${app.keycloak.realm:iam-realm}")
    private String realm;

    @Value("${app.keycloak.client-id:iam-frontend}")
    private String clientId;

    @Value("${app.keycloak.admin-client-id:iam-admin-client}")
    private String adminClientId;

    @Value("${app.keycloak.admin-client-secret:}")
    private String adminClientSecret;

    @Value("${app.keycloak.login-page-url:}")
    private String loginPageUrl;

    private final RestTemplate restTemplate = new RestTemplate();

    private Keycloak getKeycloakClient() {
        return KeycloakBuilder.builder()
                .serverUrl(authServerUrl)
                .realm(realm)
                .clientId(adminClientId)
                .clientSecret(adminClientSecret)
                .grantType(OAuth2Constants.CLIENT_CREDENTIALS)
                .build();
    }

    private UsersResource getUsersResource() {
        Keycloak keycloak = getKeycloakClient();
        RealmResource realmResource = keycloak.realm(realm);
        return realmResource.users();
    }

    /**
     * Tạo tài khoản mới trên Keycloak
     * @return Keycloak User UUID
     */
    public String createUser(String username, String email, String password, String fullName) {
        try {
            UsersResource usersResource = getUsersResource();

            // Kiểm tra username hoặc email đã có trên Keycloak chưa
            List<UserRepresentation> existingByUsername = usersResource.searchByUsername(username, true);
            if (!existingByUsername.isEmpty()) {
                throw new AppException(ErrorCode.USER_EXISTED, "Tên đăng nhập đã tồn tại trên Keycloak: " + username);
            }
            List<UserRepresentation> existingByEmail = usersResource.searchByEmail(email, true);
            if (!existingByEmail.isEmpty()) {
                throw new AppException(ErrorCode.USER_EXISTED, "Email đã tồn tại trên Keycloak: " + email);
            }

            UserRepresentation user = new UserRepresentation();
            user.setUsername(username);
            user.setEmail(email);
            user.setEnabled(true);
            user.setEmailVerified(true);
            if (fullName != null && !fullName.isBlank()) {
                String[] parts = fullName.trim().split(" ", 2);
                user.setFirstName(parts[0]);
                if (parts.length > 1) {
                    user.setLastName(parts[1]);
                }
            }

            // Mật khẩu
            if (password != null && !password.isBlank()) {
                CredentialRepresentation credential = new CredentialRepresentation();
                credential.setType(CredentialRepresentation.PASSWORD);
                credential.setValue(password);
                credential.setTemporary(false);
                user.setCredentials(Collections.singletonList(credential));
            }

            Response response = usersResource.create(user);
            int status = response.getStatus();

            if (status == 201) {
                String path = response.getLocation().getPath();
                String userId = path.replaceAll(".*/([^/]+)$", "$1");
                log.info("Successfully created Keycloak user: username={}, keycloakId={}", username, userId);

                // Kích hoạt mật khẩu trực tiếp trên Keycloak đảm bảo 100% mật khẩu hoạt động
                if (password != null && !password.isBlank()) {
                    try {
                        CredentialRepresentation credential = new CredentialRepresentation();
                        credential.setType(CredentialRepresentation.PASSWORD);
                        credential.setValue(password);
                        credential.setTemporary(false);
                        usersResource.get(userId).resetPassword(credential);
                        log.info("Activated permanent password on Keycloak for userId={}", userId);
                    } catch (Exception credEx) {
                        log.warn("Failed to reset password right after creation: {}", credEx.getMessage());
                    }
                }

                return userId;
            } else if (status == 409) {
                throw new AppException(ErrorCode.USER_EXISTED, "User đã tồn tại trên Keycloak");
            } else {
                log.error("Failed to create Keycloak user, status={}", status);
                throw new AppException(ErrorCode.KEYCLOAK_ERROR, "Không thể tạo tài khoản trên Keycloak. Mã lỗi: " + status);
            }
        } catch (AppException ae) {
            throw ae;
        } catch (Exception ex) {
            log.error("Error creating Keycloak user: ", ex);
            throw new AppException(ErrorCode.KEYCLOAK_ERROR, "Lỗi kết nối Keycloak: " + ex.getMessage());
        }
    }

    /**
     * Khóa hoặc mở khóa tài khoản trên Keycloak
     */
    public void lockUser(String keycloakId, boolean locked) {
        if (keycloakId == null || keycloakId.isBlank()) return;
        try {
            UsersResource usersResource = getUsersResource();
            UserRepresentation user = usersResource.get(keycloakId).toRepresentation();
            user.setEnabled(!locked);
            usersResource.get(keycloakId).update(user);
            log.info("Updated Keycloak user enabled={} for id={}", !locked, keycloakId);
        } catch (Exception ex) {
            log.error("Failed to lock/unlock user on Keycloak: {}", ex.getMessage());
            throw new AppException(ErrorCode.KEYCLOAK_ERROR, "Lỗi cập nhật trạng thái trên Keycloak: " + ex.getMessage());
        }
    }

    /**
     * Đặt lại mật khẩu trên Keycloak
     */
    public void resetPassword(String keycloakId, String newPassword) {
        if (keycloakId == null || keycloakId.isBlank()) return;
        try {
            UsersResource usersResource = getUsersResource();
            CredentialRepresentation credential = new CredentialRepresentation();
            credential.setType(CredentialRepresentation.PASSWORD);
            credential.setValue(newPassword);
            credential.setTemporary(false);
            usersResource.get(keycloakId).resetPassword(credential);
            log.info("Reset password on Keycloak for user id={}", keycloakId);
        } catch (Exception ex) {
            log.error("Failed to reset password on Keycloak: {}", ex.getMessage());
            throw new AppException(ErrorCode.KEYCLOAK_ERROR, "Lỗi reset mật khẩu trên Keycloak: " + ex.getMessage());
        }
    }

    /**
     * Tìm Keycloak user ID theo username hoặc email
     */
    public String findUserIdByUsernameOrEmail(String username, String email) {
        try {
            UsersResource usersResource = getUsersResource();
            if (username != null && !username.isBlank()) {
                List<UserRepresentation> list = usersResource.searchByUsername(username, true);
                if (list != null && !list.isEmpty()) {
                    return list.get(0).getId();
                }
            }
            if (email != null && !email.isBlank()) {
                List<UserRepresentation> list = usersResource.searchByEmail(email, true);
                if (list != null && !list.isEmpty()) {
                    return list.get(0).getId();
                }
            }
        } catch (Exception ex) {
            log.warn("Could not find user on Keycloak by username/email: {}", ex.getMessage());
        }
        return null;
    }

    /**
     * Xóa user trên Keycloak
     */
    public void deleteUser(String keycloakId) {
        if (keycloakId == null || keycloakId.isBlank()) return;
        try {
            UsersResource usersResource = getUsersResource();
            usersResource.get(keycloakId).remove();
            log.info("Deleted Keycloak user id={}", keycloakId);
        } catch (Exception ex) {
            log.warn("Could not delete user on Keycloak: {}", ex.getMessage());
        }
    }

    /**
     * Đăng xuất tất cả session của User trên Keycloak
     */
    public void logoutUser(String keycloakId) {
        if (keycloakId == null || keycloakId.isBlank()) return;
        try {
            UsersResource usersResource = getUsersResource();
            usersResource.get(keycloakId).logout();
            log.info("Logged out all sessions on Keycloak for user id={}", keycloakId);
        } catch (Exception ex) {
            log.warn("Could not logout user sessions on Keycloak: {}", ex.getMessage());
        }
    }

    /**
     * Đăng nhập trực tiếp (Direct Access Grants) lấy Token từ Keycloak
     */
    public TokenResponse loginDirect(String username, String password) {
        String tokenUrl = authServerUrl + "/realms/" + realm + "/protocol/openid-connect/token";

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        MultiValueMap<String, String> map = new LinkedMultiValueMap<>();
        map.add("grant_type", "password");
        map.add("client_id", clientId);
        map.add("username", username);
        map.add("password", password);

        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(map, headers);

        try {
            ResponseEntity<Map> response = restTemplate.postForEntity(tokenUrl, request, Map.class);
            Map<String, Object> body = response.getBody();
            if (body != null) {
                return TokenResponse.builder()
                        .accessToken((String) body.get("access_token"))
                        .refreshToken((String) body.get("refresh_token"))
                        .tokenType((String) body.get("token_type"))
                        .expiresIn(Long.valueOf(body.get("expires_in").toString()))
                        .build();
            }
            throw new AppException(ErrorCode.INVALID_CREDENTIALS);
        } catch (Exception ex) {
            log.error("Direct login failed on Keycloak: {}", ex.getMessage());
            throw new AppException(ErrorCode.INVALID_CREDENTIALS, "Tài khoản hoặc mật khẩu không chính xác trên Keycloak");
        }
    }

    /**
     * Refresh Token từ Keycloak
     */
    public TokenResponse refreshKeycloakToken(String refreshToken) {
        String tokenUrl = authServerUrl + "/realms/" + realm + "/protocol/openid-connect/token";

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        MultiValueMap<String, String> map = new LinkedMultiValueMap<>();
        map.add("grant_type", "refresh_token");
        map.add("client_id", clientId);
        map.add("refresh_token", refreshToken);

        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(map, headers);

        try {
            ResponseEntity<Map> response = restTemplate.postForEntity(tokenUrl, request, Map.class);
            Map<String, Object> body = response.getBody();
            if (body != null) {
                return TokenResponse.builder()
                        .accessToken((String) body.get("access_token"))
                        .refreshToken((String) body.get("refresh_token"))
                        .tokenType((String) body.get("token_type"))
                        .expiresIn(Long.valueOf(body.get("expires_in").toString()))
                        .build();
            }
            throw new AppException(ErrorCode.TOKEN_INVALID);
        } catch (Exception ex) {
            log.error("Refresh token failed on Keycloak: {}", ex.getMessage());
            throw new AppException(ErrorCode.TOKEN_EXPIRED, "Refresh token Keycloak đã hết hạn hoặc không hợp lệ");
        }
    }

    /**
     * Logout token trên Keycloak
     */
    public void logoutToken(String refreshToken) {
        if (refreshToken == null || refreshToken.isBlank()) return;
        String logoutUrl = authServerUrl + "/realms/" + realm + "/protocol/openid-connect/logout";

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        MultiValueMap<String, String> map = new LinkedMultiValueMap<>();
        map.add("client_id", clientId);
        map.add("refresh_token", refreshToken);

        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(map, headers);
        try {
            restTemplate.postForEntity(logoutUrl, request, String.class);
            log.info("Successfully revoked session on Keycloak via logout endpoint");
        } catch (Exception ex) {
            log.warn("Failed to call Keycloak logout endpoint: {}", ex.getMessage());
        }
    }

    public String getLoginPageUrl() {
        return loginPageUrl;
    }
}
