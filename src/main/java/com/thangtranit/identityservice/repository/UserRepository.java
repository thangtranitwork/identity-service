package com.thangtranit.identityservice.repository;

import com.thangtranit.identityservice.entity.Platform;
import com.thangtranit.identityservice.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<User, String> {
    Optional<User> findByEmailAndPlatform(String email, Platform platform);
    boolean existsByEmailAndPlatform(String email, Platform platform);
}
