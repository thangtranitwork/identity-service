package com.thangtranit.identityservice.service;

import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import com.thangtranit.identityservice.entity.Platform;
import com.thangtranit.identityservice.entity.User;
import com.thangtranit.identityservice.entity.SecUser;
import com.thangtranit.identityservice.exception.AppException;
import com.thangtranit.identityservice.exception.ErrorCode;
import com.thangtranit.identityservice.repository.UserRepository;

import java.util.Optional;

@Service
@RequiredArgsConstructor
@FieldDefaults(level = AccessLevel.PRIVATE, makeFinal = true)
public class SecUserService implements UserDetailsService {
    UserRepository repository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        Optional<User> user = repository.findByEmailAndPlatform(username, Platform.APP);
        return user.map(SecUser::new)
                .orElseThrow(() -> new AppException(ErrorCode.USER_NOT_EXISTS));
    }
}
