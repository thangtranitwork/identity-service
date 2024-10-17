package com.thangtranit.identityservice.dto.response;

import lombok.*;
import lombok.experimental.FieldDefaults;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
@FieldDefaults(level = AccessLevel.PRIVATE)
public class LatestMessageResponse {
    @Builder.Default
    int notReadMessagesCount = 0;
    MessageResponse message;
    UserMinimumInfoResponse friend;
}
