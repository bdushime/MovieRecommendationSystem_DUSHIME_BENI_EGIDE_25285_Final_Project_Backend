package com.example.signup.entities;

import lombok.Builder;

@Builder
public record ChangePassword(String password, String repeatPassword) {
}