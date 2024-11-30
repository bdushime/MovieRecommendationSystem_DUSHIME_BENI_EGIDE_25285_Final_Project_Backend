package com.example.signup.repository;

import com.example.signup.modal.UsersModel;
import jakarta.transaction.Transactional;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.Optional;

public interface UsersRepository extends JpaRepository<UsersModel,Integer> {
    Optional<UsersModel>findByLoginAndPasswordAndRole(String login,String password,String role);
    Optional<UsersModel>findByLogin(String login);
    Optional<UsersModel> findByEmail(String email);
    Optional<UsersModel> findByResetToken(String resetToken);

    @Transactional
    @Modifying
    @Query("UPDATE UsersModel u SET u.password = :password WHERE u.email = :email")
    void updatePassword(@Param("email") String email, @Param("password") String password);

}
