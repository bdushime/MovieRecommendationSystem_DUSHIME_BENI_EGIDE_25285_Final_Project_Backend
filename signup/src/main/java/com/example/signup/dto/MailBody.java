package com.example.signup.dto;

import lombok.Builder;

@Builder
public record MailBody(String to, String subject, String text) {

}
