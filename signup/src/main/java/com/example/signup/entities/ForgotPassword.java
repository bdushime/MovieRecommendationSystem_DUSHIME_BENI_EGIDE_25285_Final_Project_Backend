package com.example.signup.entities;

import com.example.signup.modal.UsersModel;
import jakarta.persistence.*;
import lombok.Builder;
import lombok.Getter;
import lombok.Setter;

import java.util.Date;

@Entity
@Getter
@Setter
@Builder
public class ForgotPassword {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Integer fpid;
    private Integer otp;
    private Date expirationTime;

    @OneToOne
    private UsersModel user;

    public ForgotPassword() {
    }

    public ForgotPassword(Integer fpid, Integer otp, Date expirationTime, UsersModel user) {
        this.fpid = fpid;
        this.otp = otp;
        this.expirationTime = expirationTime;
        this.user = user;
    }
}