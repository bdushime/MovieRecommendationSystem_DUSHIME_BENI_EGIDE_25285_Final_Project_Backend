package com.example.signup.repository;

import com.example.signup.modal.UsersModel;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface ResetTokenRepository extends JpaRepository<ResetToken, Long> {
    void deleteByToken(String token);
    Optional<ResetToken> findByUser(Optional<UsersModel> user);
    Optional<ResetToken> findByToken(String token);
}
