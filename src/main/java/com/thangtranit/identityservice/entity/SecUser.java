package com.thangtranit.identityservice.entity;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;

public class SecUser implements UserDetails {
    private final String name;
    private final String password;
    private final List<GrantedAuthority> authorities;

    public SecUser(User user) {
        name = user.getEmail();
        password = user.getPassword();
        System.out.println(password);
        authorities = Arrays.stream(user.getRoles().split(" "))
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toList());
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return authorities;
    }

    @Override
    public String getPassword() {
        return this.password;
    }

    @Override
    public String getUsername() {
        return this.name;
    }

}
