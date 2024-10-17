package com.thangtranit.identityservice.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import com.thangtranit.identityservice.entity.LoggedOutToken;

@Repository
public interface LoggedOutTokenRepository extends JpaRepository<LoggedOutToken, String> {
}
