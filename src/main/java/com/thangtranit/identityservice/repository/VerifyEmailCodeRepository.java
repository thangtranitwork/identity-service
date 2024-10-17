package com.thangtranit.identityservice.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import com.thangtranit.identityservice.entity.VerifyEmailCode;

import java.util.Optional;

@Repository
public interface VerifyEmailCodeRepository extends JpaRepository<VerifyEmailCode, String> {
    Optional<VerifyEmailCode> findByUserEmail(String email);
}
