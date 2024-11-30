//package com.example.signup.controller;
//
//import com.example.signup.EmailService;
//import com.example.signup.ForgotPasswordRepository;
//import com.example.signup.modal.UsersModel;
//import com.example.signup.repository.UsersRepository;
//import com.example.signup.dto.MailBody;
//import com.example.signup.entities.ForgotPassword;
//import com.example.signup.entities.ChangePassword;
//import org.springframework.http.HttpStatus;
//import org.springframework.http.ResponseEntity;
//import org.springframework.security.core.userdetails.UsernameNotFoundException;
//import org.springframework.security.crypto.password.PasswordEncoder;
//import org.springframework.stereotype.Controller;
//import org.springframework.ui.Model;
//import org.springframework.web.bind.annotation.*;
//import org.springframework.web.servlet.mvc.support.RedirectAttributes;
//
//import java.time.Instant;
//import java.util.Date;
//import java.util.Objects;
//import java.util.Random;
//
//@Controller
//@RequestMapping("/forgotPassword")
//public class ForgotPasswordController {
//    private final UsersRepository users;
//    private final EmailService emailService;
//    private final ForgotPasswordRepository forgotPasswordRepository;
//    private final PasswordEncoder passwordEncoder;
//
//    public ForgotPasswordController(UsersRepository users, EmailService emailService, ForgotPasswordRepository forgotPasswordRepository, PasswordEncoder passwordEncoder) {
//        this.users = users;
//        this.emailService = emailService;
//        this.forgotPasswordRepository = forgotPasswordRepository;
//        this.passwordEncoder = passwordEncoder;
//    }
//
//    // Generate OTP
//    private Integer otpGenerator() {
//        Random random = new Random();
//        return random.nextInt(900000) + 100000;
//    }
//
//    @PostMapping("/verifyMail")
//    public String verifyEmail(@RequestParam String email, RedirectAttributes redirectAttributes) {
//        try {
//            UsersModel usersModel = users.findByEmail(email)
//                    .orElseThrow(() -> new UsernameNotFoundException("Please provide a valid email"));
//
//            Integer otp = otpGenerator();
//            MailBody mailBody = MailBody.builder()
//                    .to(email)
//                    .text("This is the OTP for your forgot password: " + otp)
//                    .subject("OTP for Forgot Password request")
//                    .build();
//
//            ForgotPassword fp = ForgotPassword.builder()
//                    .otp(otp)
//                    .expirationTime(new Date(System.currentTimeMillis() + 70 * 1000))
//                    .user(usersModel)
//                    .build();
//
//            emailService.sendSimpleMessage(mailBody);
//            forgotPasswordRepository.save(fp);
//
//            // Add email as a flash attribute for the next page
//            redirectAttributes.addFlashAttribute("email", email);
//
//            return "redirect:/resetPassword";  // This will now actually redirect
//        } catch (UsernameNotFoundException e) {
//            redirectAttributes.addFlashAttribute("error", "Email not found");
//            return "redirect:/forgotPassword";
//        }
//    }
//
//    // Verify OTP
//    @PostMapping("/verifyOtp/{otp}/{email}")
//    public ResponseEntity<String> verifyOtp(@PathVariable Integer otp, @PathVariable String email) {
//        UsersModel usersModel = users.findByEmail(email)
//                .orElseThrow(() -> new UsernameNotFoundException("Please provide a valid email"));
//
//        ForgotPassword fp = forgotPasswordRepository.findByOtpAndUser(otp, usersModel)
//                .orElseThrow(() -> new RuntimeException("Invalid OTP for email: " + email));
//
//        if (fp.getExpirationTime().before(Date.from(Instant.now()))) {
//            forgotPasswordRepository.deleteById(fp.getFpid());
//            return new ResponseEntity<>("OTP has expired", HttpStatus.EXPECTATION_FAILED);
//        }
//
//        return ResponseEntity.ok("OTP verified!");
//    }
//
//
//    @PostMapping("/changePassword/{email}")
//    public String changePasswordHandler(
//            @RequestParam String password,
//            @RequestParam String repeatPassword,
//            @PathVariable String email,
//            RedirectAttributes redirectAttributes) {
//
//        if (!Objects.equals(password, repeatPassword)) {
//            redirectAttributes.addFlashAttribute("error", "Passwords do not match. Please try again!");
//            return "redirect:/resetPassword";
//        }
//
//        try {
//            String encodedPassword = passwordEncoder.encode(password);
//            users.updatePassword(email, encodedPassword);
//
//            redirectAttributes.addFlashAttribute("success", "Password has been changed successfully.");
//            return "redirect:/login";
//        } catch (Exception e) {
//            redirectAttributes.addFlashAttribute("error", "Failed to update password. Please try again.");
//            return "redirect:/resetPassword";
//        }
//    }
//
//    // Add this method to handle displaying the reset password page
//    @GetMapping("/resetPassword")
//    public String showResetPasswordPage(@RequestParam(required = false) String email, Model model) {
//        if (email != null) {
//            model.addAttribute("email", email);
//        }
//        return "resetPassword";
//    }
//}
