package com.thangtranit.identityservice.mapper;

import com.thangtranit.identityservice.dto.request.OAuth2RegisterRequest;
import com.thangtranit.identityservice.dto.request.RegisterRequest;
import com.thangtranit.identityservice.dto.response.UserAdminViewResponse;
import com.thangtranit.identityservice.entity.User;
import org.mapstruct.Mapper;
import org.mapstruct.NullValueMappingStrategy;

@Mapper(componentModel = "spring", nullValueMappingStrategy = NullValueMappingStrategy.RETURN_DEFAULT)
public interface UserMapper {
    User toUser(RegisterRequest request);

    User toUser(OAuth2RegisterRequest request);

    UserAdminViewResponse toUserAdminViewResponse(User user);

}
