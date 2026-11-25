package com.iam.exception;

import lombok.Getter;
import org.springframework.http.HttpStatus;

@Getter
public enum ErrorCode {
    UNCATEGORIZED_EXCEPTION("Lỗi hệ thống không xác định", HttpStatus.INTERNAL_SERVER_ERROR),
    INVALID_KEY("Khóa không hợp lệ", HttpStatus.BAD_REQUEST),
    USER_NOT_FOUND("Không tìm thấy người dùng", HttpStatus.NOT_FOUND),
    USER_EXISTED("Tên đăng nhập hoặc email đã tồn tại", HttpStatus.CONFLICT),
    USER_LOCKED("Tài khoản đã bị khóa", HttpStatus.FORBIDDEN),
    USER_DELETED("Tài khoản đã bị xóa", HttpStatus.GONE),
    INVALID_CREDENTIALS("Tên đăng nhập hoặc mật khẩu không chính xác", HttpStatus.UNAUTHORIZED),
    UNAUTHENTICATED("Chưa xác thực danh tính", HttpStatus.UNAUTHORIZED),
    UNAUTHORIZED("Bạn không có quyền thực hiện hành động này", HttpStatus.FORBIDDEN),
    ROLE_NOT_FOUND("Không tìm thấy vai trò", HttpStatus.NOT_FOUND),
    ROLE_EXISTED("Mã vai trò đã tồn tại", HttpStatus.CONFLICT),
    PERMISSION_NOT_FOUND("Không tìm thấy quyền", HttpStatus.NOT_FOUND),
    PERMISSION_EXISTED("Mã quyền đã tồn tại", HttpStatus.CONFLICT),
    CANNOT_DELETE_SYSTEM_ROLE("Không thể xóa vai trò hệ thống", HttpStatus.BAD_REQUEST),
    INVALID_REQUEST("Yêu cầu không hợp lệ", HttpStatus.BAD_REQUEST),
    INTERNAL_SERVER_ERROR("Lỗi hệ thống nội bộ", HttpStatus.INTERNAL_SERVER_ERROR),
    TOKEN_EXPIRED("Token đã hết hạn", HttpStatus.UNAUTHORIZED),
    TOKEN_INVALID("Token không hợp lệ", HttpStatus.UNAUTHORIZED),
    KEYCLOAK_ERROR("Lỗi tương tác với Identity Server Keycloak", HttpStatus.BAD_GATEWAY);

    private final String message;
    private final HttpStatus httpStatus;

    ErrorCode(String message, HttpStatus httpStatus) {
        this.message = message;
        this.httpStatus = httpStatus;
    }
}
