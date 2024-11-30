package com.example.signup.reset;

public class InvalidPasswordExceptio extends RuntimeException {
    public InvalidPasswordExceptio(String message) {
        super(message);
    }

    public InvalidPasswordExceptio(String message, Throwable cause) {
        super(message, cause);
    }
}