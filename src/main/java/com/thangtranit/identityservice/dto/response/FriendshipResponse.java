package com.thangtranit.identityservice.dto.response;

import lombok.*;
import lombok.experimental.FieldDefaults;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
@FieldDefaults(level = AccessLevel.PRIVATE)
public class FriendshipResponse {
    String id;
    UserMinimumInfoResponse a;
    UserMinimumInfoResponse b;
    boolean accepted;
}
