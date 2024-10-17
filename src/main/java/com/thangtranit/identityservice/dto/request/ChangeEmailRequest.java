package com.thangtranit.identityservice.dto.request;

import jakarta.validation.constraints.Email;
import lombok.*;
import lombok.experimental.FieldDefaults;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
@FieldDefaults(level = AccessLevel.PRIVATE)
public class ChangeEmailRequest {
    @Email(message = "INVALID_NEW_EMAIL")
    String email;
}
