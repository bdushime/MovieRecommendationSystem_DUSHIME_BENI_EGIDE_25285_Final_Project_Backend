//package com.example.signup.controller;
//
//import com.example.signup.EmailService;
//import com.example.signup.modal.UsersModel;
//import com.example.signup.repository.UsersRepository;
//import org.slf4j.Logger;
//import org.slf4j.LoggerFactory;
//import org.springframework.beans.factory.annotation.Autowired;
//import org.springframework.stereotype.Controller;
//import org.springframework.ui.Model;
//import org.springframework.web.bind.annotation.GetMapping;
//import org.springframework.web.bind.annotation.PostMapping;
//import org.springframework.web.bind.annotation.RequestParam;
//import org.springframework.web.servlet.mvc.support.RedirectAttributes;
//
//import java.time.LocalDateTime;
//import java.util.Optional;
//import java.util.UUID;
//
//@Controller
//public class AuthController {
//
//    @Autowired
//    private UsersRepository userRepository;
//    private static final Logger logger = LoggerFactory.getLogger(AuthController.class);
//
//    @Autowired
//    private EmailService emailService;
//
//    @GetMapping("/forgotPassword")
//    public String forgotPassword() {
//        logger.info("Accessing forgot password page");
//        try {
//            return "forgotPassword"; // Should map to forgot-password.html
//        } catch (Exception e) {
//            logger.error("Error accessing forgot password page: ", e);
//            return "error";
//        }
//        return "forgotPassword"; // Maps to forgot-password.html
//    }
//
//    @PostMapping("/forgotPassword")
//    public String handleForgotPassword(@RequestParam("email") String email, RedirectAttributes redirectAttributes) {
//        Optional<UsersModel> userOptional = userRepository.findByEmail(email);
//
//        if (userOptional.isPresent()) {
//            UsersModel user = userOptional.get();
//
//            // Generate a unique reset token
//            String resetToken = UUID.randomUUID().toString();
//            user.setResetToken(resetToken);
//            user.setTokenExpiry(LocalDateTime.now().plusHours(1)); // Token expires in 1 hour
//
//            userRepository.save(user);
//
//            // Generate reset link
//            String resetLink = "http://localhost:8080/reset-password?token=" + resetToken;
//
//            // Send email
//            emailService.sendResetPasswordEmail(user.getEmail(), resetLink);
//
//            redirectAttributes.addAttribute("success", true);
//        } else {
//            redirectAttributes.addAttribute("error", true);
//        }
//
//        return "redirect:/forgotPassword";
//    }
//
//    @GetMapping("/resetPassword")
//    public String showResetPasswordForm(@RequestParam("token") String token, Model model) {
//        Optional<UsersModel> userOptional = userRepository.findByResetToken(token);
//
//        if (userOptional.isPresent() && userOptional.get().getTokenExpiry().isAfter(LocalDateTime.now())) {
//            model.addAttribute("token", token);
//            return "resetPassword"; // Point to reset-password.html form
//        } else {
//            return "redirect:/forgotPassword?error=invalidToken";
//        }
//    }
//
//    @PostMapping("/resetPassword")
//    public String handleResetPassword(@RequestParam("token") String token,
//                                      @RequestParam("newPassword") String newPassword,
//                                      RedirectAttributes redirectAttributes) {
//        Optional<UsersModel> userOptional = userRepository.findByResetToken(token);
//
//        if (userOptional.isPresent() && userOptional.get().getTokenExpiry().isAfter(LocalDateTime.now())) {
//            UsersModel user = userOptional.get();
//            user.setPassword(newPassword); // Ensure password is hashed in production
//            user.setResetToken(null);
//            user.setTokenExpiry(null);
//            userRepository.save(user);
//
//            redirectAttributes.addAttribute("success", "Password reset successfully");
//            return "redirect:/login";
//        } else {
//            redirectAttributes.addAttribute("error", "Invalid or expired token");
//            return "redirect:/forgotPassword";
//        }
//    }
//
//}
