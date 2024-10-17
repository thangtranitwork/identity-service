package com.thangtranit.identityservice.controller;

import com.thangtranit.identityservice.dto.request.AuthenticationRequest;
import com.thangtranit.identityservice.dto.request.OAuth2RegisterRequest;
import com.thangtranit.identityservice.entity.Platform;
import com.thangtranit.identityservice.entity.Role;
import com.thangtranit.identityservice.exception.AppException;
import com.thangtranit.identityservice.exception.ErrorCode;
import com.thangtranit.identityservice.service.AuthenticationService;
import com.thangtranit.identityservice.service.RegisterService;
import com.thangtranit.identityservice.service.UserService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import java.io.IOException;

public class CustomOAuth2LoginSuccessHandler implements AuthenticationSuccessHandler {

    @Autowired
    private UserService userService;
    @Autowired
    private RegisterService registerService;
    @Autowired
    private AuthenticationService authenticationService;
    @Value("${FE_ORIGIN}")
    private String FE_ORIGIN;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException {
        OAuth2AuthenticationToken oAuth2AuthenticationToken = (OAuth2AuthenticationToken) authentication;
        String email;
        try {
            email = oAuth2AuthenticationToken.getPrincipal().getAttributes().get("email").toString();
        } catch (NullPointerException e) {
            throw new AppException(ErrorCode.OAUTH2_LOGIN_HAS_NO_EMAIL);
        }
        String platform = oAuth2AuthenticationToken.getAuthorizedClientRegistrationId().toUpperCase();

        if (!userService.checkExists(email, Platform.valueOf(platform))) {
            {
                OAuth2RegisterRequest registerRequest = OAuth2RegisterRequest.builder()
                        .email(email)
                        .platform(platform)
                        .roles(Role.OAUTH2.name())
                        .build();
                registerService.register(registerRequest);

            }
        }
        authenticationService.oauth2LoginAuthenticate(
                AuthenticationRequest.builder()
                .email(email)
                .platform(platform)
                        .build(),
                response);

        response.sendRedirect(FE_ORIGIN + "/login");
    }
}

