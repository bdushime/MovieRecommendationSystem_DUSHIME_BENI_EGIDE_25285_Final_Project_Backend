//package com.example.signup;
//
//import com.example.signup.controller.UsersController;
//import com.example.signup.dto.MailBody;
//import jakarta.mail.internet.MimeMessage;
//import lombok.extern.slf4j.Slf4j;
//import org.slf4j.Logger;
//import org.slf4j.LoggerFactory;
//import org.springframework.beans.factory.annotation.Autowired;
//import org.springframework.beans.factory.annotation.Value;
//import org.springframework.mail.SimpleMailMessage;
//import org.springframework.mail.javamail.JavaMailSender;
//import org.springframework.mail.javamail.MimeMessageHelper;
//import org.springframework.stereotype.Service;
//
//@Service
//@Slf4j
//public class EmailService {
//    @Autowired
//    private JavaMailSender mailSender;
//
//    @Value("${spring.mail.username}")
//    private String fromEmail;
//
//    @Value("${app.base-url}")
//    private String baseUrl;
//
//    private static final Logger log = LoggerFactory.getLogger(UsersController.class);
//
//    public void sendPasswordResetEmail(String toEmail, String token) {
//        try {
//            MimeMessage message = mailSender.createMimeMessage();
//            MimeMessageHelper helper = new MimeMessageHelper(message, true, "UTF-8");
//
//            helper.setFrom(fromEmail);
//            helper.setTo(toEmail);
//            helper.setSubject("Beniflix - Password Reset Request");
//
//            String htmlContent = createPasswordResetEmailContent(token);
//            helper.setText(htmlContent, true);
//
//            mailSender.send(message);
//            log.info("Password reset email sent successfully to: {}", toEmail);
//        } catch (Exception e) {
//            log.error("Failed to send password reset email to: {}", toEmail, e);
////            throw new EmailSendException("Failed to send password reset email", e);
//        }
//    }
//
//    private String createPasswordResetEmailContent(String token) {
//        String resetLink = baseUrl + "/resetPassword?token=" + token;
//
//        return """
//            <html>
//                <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
//                    <div style="max-width: 600px; margin: 0 auto; padding: 20px;">
//                        <h2 style="color: #e50914;">Beniflix Password Reset</h2>
//                        <p>Hello,</p>
//                        <p>We received a request to reset your Beniflix account password.</p>
//                        <p>Click the button below to reset your password:</p>
//                        <p style="text-align: center;">
//                            <a href="%s"
//                               style="background-color: #e50914;
//                                      color: white;
//                                      padding: 12px 24px;
//                                      text-decoration: none;
//                                      border-radius: 4px;
//                                      display: inline-block;">
//                                Reset Password
//                            </a>
//                        </p>
//                        <p>This link will expire in 24 hours.</p>
//                        <p>If you didn't request this password reset, please ignore this email.</p>
//                        <hr style="border: 1px solid #eee; margin: 20px 0;">
//                        <p style="color: #666;">
//                            Thanks,<br>
//                            The Beniflix Team
//                        </p>
//                    </div>
//                </body>
//            </html>
//            """.formatted(resetLink);
//    }
//}
