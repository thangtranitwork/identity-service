package com.thangtranit.identityservice.controller;

import com.thangtranit.identityservice.dto.request.ChangeEmailRequest;
import com.thangtranit.identityservice.dto.request.ChangePasswordRequest;
import com.thangtranit.identityservice.dto.request.OtpVerifyRequest;
import com.thangtranit.identityservice.dto.response.ApiResponse;
import com.thangtranit.identityservice.dto.response.ChangeEmailResponse;
import com.thangtranit.identityservice.dto.response.OtpVerifyResponse;
import com.thangtranit.identityservice.dto.response.UserProfileResponse;
import com.thangtranit.identityservice.service.UserService;
import jakarta.validation.Valid;
import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/users")
@RequiredArgsConstructor
@FieldDefaults(level = AccessLevel.PRIVATE)
public class UserController {
    final UserService userService;

    @GetMapping("/{id}")
    ApiResponse<UserProfileResponse> getUserProfile(@PathVariable String id) {
        return ApiResponse.<UserProfileResponse>builder()
                .body(userService.getProfile(id))
                .build();
    }

    @GetMapping("/profile")
    ApiResponse<UserProfileResponse> getProfile(){
        return ApiResponse.<UserProfileResponse>builder()
                .body(userService.getProfile())
                .build();
    }

    @GetMapping({"/update/email", "/update/password"})
    ApiResponse<Void> prepareForChangeLoginInfo() {
        userService.prepare();
        return ApiResponse.<Void>builder()
                .build();
    }

    @PostMapping({"/update/email/verify-otp", "/update/password/verify-otp"})
    ApiResponse<OtpVerifyResponse> verifyOtp(@RequestBody @Valid OtpVerifyRequest request) {
        return ApiResponse.<OtpVerifyResponse>builder()
                .body(userService.verifyOtp(request))
                .build();
    }

    @PutMapping("/update/email")
    ApiResponse<ChangeEmailResponse> changeUserEmail(@RequestBody @Valid ChangeEmailRequest request) {
        return ApiResponse.<ChangeEmailResponse>builder()
                .body(userService.changeEmail(request))
                .build();
    }

    @PutMapping("/update/password")
    ApiResponse<Void> changeUserPassword(@RequestBody @Valid ChangePasswordRequest request) {
        userService.changePassword(request);
        return ApiResponse.<Void>builder()
                .build();
    }

    @DeleteMapping("/delete")
    ApiResponse<Void> deleteUser() {
        userService.delete();
        return ApiResponse.<Void>builder()
                .build();
    }
}
