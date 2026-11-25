# IAM Service 2 - Hệ Thống Quản Lý Định Danh Và Phân Quyền (Identity & Access Management)

Hệ thống **IAM Service 2** là giải pháp quản lý định danh và truy cập toàn diện được xây dựng trên nền tảng **Spring Boot 3.3.5 (Java 21)**. Dự án đáp ứng kiến trúc linh hoạt **Dual-IDP**, cho phép chuyển đổi nóng giữa **Keycloak Identity Server** và **Self-IDP (JWT nội bộ)** chỉ bằng một dòng cấu hình, kết hợp với mô hình phân quyền động **RBAC (Role-Based Access Control)**, cơ chế **Xóa mềm (Soft Delete)** và **Kiểm toán dữ liệu (Auditing)**.

---

## 🚀 Công Nghệ Sử Dụng

* **Ngôn ngữ & Nền tảng:** Java 21, Spring Boot 3.3.5
* **Security & Token:** 
  * Spring Security 6, OAuth2 Resource Server
  * Keycloak Admin Client (v26.0.0)
  * JJWT (Java JWT v0.12.6)
* **Cơ sở dữ liệu:** Microsoft SQL Server 2022, Spring Data JPA, Hibernate 6
* **Tài liệu API:** Springdoc OpenAPI 3 (Swagger UI v2.6.0)
* **Logging:** SLF4J, Logback (Daily Time-based Rolling, Sensitive Data Masking)
* **Build Tool:** Maven Wrapper (`mvnw`)

---

## 🌟 Các Chức Năng Nổi Bật & Tâm Đắc

### 1. Kiến Trúc Dual-IDP Chuyển Đổi Linh Hoạt (Keycloak & Self-IDP)
* **Bật Keycloak (`app.idp.provider: keycloak`):**
  * Đăng nhập: Gọi `/api/auth/login` cung cấp đường dẫn đăng nhập Keycloak hoặc đăng nhập trực tiếp (Direct Access Grants).
  * Xác thực kép: Khi người dùng đính kèm Bearer Access Token vào request, hệ thống giải mã token Keycloak và **bắt buộc kiểm tra sự tồn tại, trạng thái khóa và xóa mềm của user trong Database nội bộ của IAM** trước khi thực thi nghiệp vụ.
  * Đồng bộ 2 chiều: Đăng ký, tạo user, khóa tài khoản, đổi mật khẩu và xóa user đều được tự động đồng bộ sang Keycloak thông qua `KeycloakAdminService`.
  * Đăng xuất & Refresh Token gọi trực tiếp API Keycloak.
* **Tắt Keycloak (`app.idp.provider: self`):**
  * Tự động chuyển sang sử dụng bảng `users` nội bộ.
  * Tự sinh và xác thực Access Token (1 giờ) và Refresh Token (7 ngày).

### 2. Phân Quyền Động RBAC Với `@PreAuthorize("hasPermission(...)")`
* Cung cấp trọn bộ CRUD Quyền (`permissions`), CRUD Vai trò (`roles`), Gán quyền cho vai trò và Gán vai trò cho user.
* Tùy biến `CustomPermissionEvaluator`: Kiểm tra quyền hạn trực tiếp theo chuẩn `resource:action` (ví dụ: `USER:CREATE`, `ROLE:READ`). Quản trị hệ thống (`SYSTEM_ADMIN`) được phân quyền toàn năng.

### 3. Tự Động Xóa Mềm (Soft Delete) & Auditing Minh Bạch
* Toàn bộ 7 bảng trong hệ thống đều kế thừa `BaseEntity`.
* Sử dụng `@SQLDelete` và `@SQLRestriction("deleted = 0")` của Hibernate 6: Không làm mất dữ liệu vật lý, mọi truy vấn tìm kiếm tự động lọc bỏ bản ghi đã xóa.
* `AuditorAware`: Tự động ghi nhận `created_by`, `created_at`, `updated_by`, `updated_at` từ `SecurityContextHolder`.

### 4. Ghi Log Rolling Theo Ngày & Bảo Mật Dữ Liệu Nhạy Cảm (Masking)
* Cấu hình `logback-spring.xml` lưu file log tự động theo từng ngày (`logs/iam-service-2-yyyy-MM-dd.log`).
* `RequestResponseLoggingFilter`: Ghi log toàn bộ URI, HTTP Method, HTTP Status và thời gian xử lý; sử dụng Regex tự động che giấu (`***MASKED***`) các trường `password`, `oldPassword`, `newPassword`, `clientSecret`, `refreshToken`.

---

## ⚙️ Cấu Hình Hệ Thống

File cấu hình tại `src/main/resources/application.yml`:

```yaml
# Chọn chế độ: 'keycloak' hoặc 'self'
app:
  idp:
    provider: keycloak 
  keycloak:
    auth-server-url: http://localhost:8180
    realm: iam-realm
    client-id: iam-frontend
    admin-client-id: iam-admin-client
    admin-client-secret: gRteLWut1BX6oVkBSmZexeV5wf6IwNMg8GaUFv94fpvragDBBTM04gmThFU29J5uDzGduVeHhs9keWAhrWABJX
```

---

## 🛠️ Hướng Dẫn Chạy Ứng Dụng

### 1. Khởi động Keycloak (Nếu dùng chế độ Keycloak)
```powershell
cd C:\keycloak-26.8.2\bin
.\kc.bat start-dev --http-port=8180
```

### 2. Khởi động Backend Spring Boot
Mở thư mục `IAM_2_BE` và chạy lệnh thông qua Maven Wrapper:
```powershell
cd IAM_2_BE
.\mvnw spring-boot:run
```

Truy cập Swagger UI để xem và thử nghiệm toàn bộ API:
👉 **[http://localhost:8080/swagger-ui.html](http://localhost:8080/swagger-ui.html)**

---

## 🔑 Tài Khoản Mặc Định Sẵn Có

| Chế độ | Tên đăng nhập | Mật khẩu | Vai trò | Ghi chú |
| :--- | :--- | :--- | :--- | :--- |
| **Keycloak** | `testuser2026@gmail.com` | `123456` | `SYSTEM_ADMIN` | Đã đồng bộ sẵn trong DB IAM |
| **Self-IDP** | `admin` | `Admin@123` | `SYSTEM_ADMIN` | Khởi tạo tự động qua DataInitializer |

---

## 📋 Kịch Bản Demo (5 - 7 Phút)

1. **Phút 1:** Mở Swagger UI, giới thiệu tổng thể tài liệu API và cấu trúc Dual-IDP.
2. **Phút 2 - 3 (Chế độ Keycloak):**
   * Đăng nhập lấy Bearer Token qua API `/api/auth/login`.
   * Gắn Bearer Token vào Swagger (nút Authorize).
   * Gọi API tạo user mới: Chứng minh user xuất hiện ở cả Database IAM và Keycloak Admin Console.
   * Gọi API Khóa user / Xóa mềm user: Kiểm tra user bị vô hiệu hóa, không gọi tiếp được các request nghiệp vụ.
3. **Phút 4 - 5 (Chế độ Self-IDP):**
   * Đổi `app.idp.provider: self` trong `application.yml` -> Restart.
   * Đăng nhập tài khoản `admin` / `Admin@123` -> Lấy JWT nội bộ.
   * Thử nghiệm phân quyền RBAC: Tạo role, gán permission và test `@PreAuthorize("hasPermission(...)")`.
4. **Phút 6 - 7:** Mở thư mục `logs/` để kiểm tra file log theo ngày và chứng minh mật khẩu đã được che giấu (`***MASKED***`).
