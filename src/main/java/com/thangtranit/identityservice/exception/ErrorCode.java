package com.thangtranit.identityservice.exception;

import lombok.Getter;
import org.springframework.http.HttpStatus;

@Getter
public enum ErrorCode {
    // Các mã lỗi liên quan đến người dùng (100-199)
    USER_ALREADY_EXISTS(100, "Người dùng đã tồn tại", HttpStatus.CONFLICT),
    USER_NOT_EXISTS(101, "Người dùng không tồn tại", HttpStatus.NOT_FOUND),
    INVALID_EMAIL(102, "Email không hợp lệ", HttpStatus.BAD_REQUEST),
    INVALID_PASSWORD(103, "Mật khẩu phải có ít nhất 8 ký tự", HttpStatus.BAD_REQUEST),
    LOGIN_FAILED(104, "Đăng nhập thất bại, vui lòng kiểm tra thông tin đăng nhập", HttpStatus.UNAUTHORIZED),
    OTP_NOT_FOUND(105, "Chưa xác minh OTP hoặc OTP trước đó đã hết hạn", HttpStatus.NOT_FOUND),
    OTP_HAS_ALREADY_EXPIRED(106, "OTP đã hết hạn", HttpStatus.GONE),
    NO_EMAIL_USER(107, "Không có người dùng nào sử dụng email này", HttpStatus.NOT_FOUND),
    EMAIL_HAS_BEEN_USED(108, "Email đã được sử dụng", HttpStatus.CONFLICT),
    INVALID_NEW_PASSWORD(109, "Mật khẩu mới phải có ít nhất 8 ký tự", HttpStatus.BAD_REQUEST),
    INVALID_NEW_EMAIL(110, "Email mới không hợp lệ", HttpStatus.BAD_REQUEST),
    OTP_NOT_VERIFIED(111, "OTP chưa được xác minh", HttpStatus.FORBIDDEN),
    OAUTH2_LOGIN_HAS_NO_EMAIL(112, "Đăng nhập bằng OAuth2 không có email", HttpStatus.BAD_REQUEST),
    USER_HAS_NOT_VERIFIED_EMAIL(115, "Người dùng này chưa xác minh email", HttpStatus.FORBIDDEN),
    OLD_EMAIL_AND_NEW_EMAIL_ARE_THE_SAME(116, "Email cũ và email mới giống nhau", HttpStatus.BAD_REQUEST),
    OAUTH2_USER_CAN_NOT_CHANGE_LOGIN_INFO(118, "Người dùng OAuth2 không thể thay đổi thông tin đăng nhập", HttpStatus.FORBIDDEN),
    VERIFY_CODE_DOES_NOT_EXIST(120, "Không tồn tại mã xác thực này", HttpStatus.NOT_FOUND),
    VERIFY_CODE_TIMEOUT(121, "Mã xác thực đã hết hạn", HttpStatus.GONE),
    VERIFY_CODE_INVALID(122, "Mã xác thực không hợp lệ", HttpStatus.BAD_REQUEST),
    OTP_HAS_EXCEED_THE_NUMBER_OF_TRIES(123, "OTP đã vượt quá số lần thử", HttpStatus.FORBIDDEN),
    OTP_INVALID(123, "OTP không hợp lệ", HttpStatus.BAD_REQUEST),
    THIS_USER_HAS_BEEN_LOCKED(124, "Người dùng này đã bị khóa do nhập sai mật khẩu nhiều lần", HttpStatus.LOCKED),
    // Các mã lỗi liên quan đến token (300-399)
    TOKEN_IS_EXPIRED_OR_INVALID(300, "Token đã hết hạn hoặc không hợp lệ", HttpStatus.UNAUTHORIZED),
    TOKEN_HAS_BEEN_LOGGED_OUT(301, "Token đã bị đăng xuất", HttpStatus.UNAUTHORIZED),
    // Các mã lỗi liên quan đến truy cập (400-499)
    ACCESS_DENIED(403, "Không có quyền xem hoặc chỉnh sửa tài nguyên này", HttpStatus.FORBIDDEN),
    UNAUTHENTICATED(401, "Chưa xác thực", HttpStatus.UNAUTHORIZED),
    NO_RESOURCE_FOUND(404, "Không tồn tại", HttpStatus.NOT_FOUND),

    ROLE_IS_INVALID(901, "Phân quyền không hợp lệ", HttpStatus.BAD_REQUEST),
    USER_HAS_ALREADY_HAVE_THE_ROLE(902, "Người dùng này đã có quyền này", HttpStatus.CONFLICT),
    USER_DOES_NOT_HAVE_THE_ROLE(903, "Người dùng nay không có quyền này", HttpStatus.CONFLICT),
    CANT_NOT_SEFT_REVOKE_YOUR_ROLES(904, "Không thể tự thu hồi quyền của chính mình", HttpStatus.BAD_REQUEST),
    // Lỗi không phân loại
    UNCATEGORIZED_ERROR(1000, "Lỗi không phân loại", HttpStatus.INTERNAL_SERVER_ERROR),
    NEED_CHANGE(0, "Sửa mã lỗi dùm cái", HttpStatus.BAD_REQUEST),
    ;

    private final int code;
    private final String message;
    private final HttpStatus status;

    ErrorCode(int code, String message, HttpStatus status) {
        this.code = code;
        this.message = message;
        this.status = status;
    }
}
