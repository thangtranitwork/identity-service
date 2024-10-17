package com.thangtranit.identityservice.dto.request;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.Size;
import lombok.*;
import lombok.experimental.FieldDefaults;
import com.thangtranit.identityservice.entity.Platform;
import com.thangtranit.identityservice.entity.Role;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
@FieldDefaults(level = AccessLevel.PRIVATE)
public class RegisterRequest {
    @Email(message = "INVALID_EMAIL")
    String email;
    @Size(min = 8, message = "INVALID_PASSWORD")
    String password;
    @Builder.Default
    String roles = Role.USER.name();
    @Builder.Default
    String platform = Platform.APP.name();
}
