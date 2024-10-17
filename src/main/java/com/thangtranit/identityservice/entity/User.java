package com.thangtranit.identityservice.entity;

import jakarta.persistence.*;
import lombok.*;
import lombok.experimental.FieldDefaults;

import java.time.LocalDateTime;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Entity
@Builder
@FieldDefaults(level = AccessLevel.PRIVATE)
@Table(name = "user",
        uniqueConstraints = {@UniqueConstraint(name = "unique_email_platform", columnNames = {"email", "platform"})}
)
public class User {
    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    @Column(name = "user_id")
    String id;
    @Column(nullable = false)
    String email;
    String password;
    String roles;
    @Enumerated(EnumType.STRING)
    Platform platform;
    LocalDateTime lastOnline;
    boolean isVerified;
    boolean accountLocked;
    int failedAttempts;
    LocalDateTime lockoutTime;
    @OneToOne(mappedBy = "user", cascade = CascadeType.ALL)
    @ToString.Exclude
    Otp otp;
    @OneToOne(mappedBy = "user")
    @ToString.Exclude
    VerifyEmailCode verifyEmailCode;

}
