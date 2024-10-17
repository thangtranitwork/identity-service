package com.thangtranit.identityservice.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;
import com.thangtranit.identityservice.entity.Otp;

import java.util.Optional;

@Repository
public interface OtpRepository extends JpaRepository<Otp, String> {
   // @Query("SELECT o FROM Otp o WHERE o.user.email = :email")

    Optional<Otp>  findByUserEmail(@Param("email") String email);
}
