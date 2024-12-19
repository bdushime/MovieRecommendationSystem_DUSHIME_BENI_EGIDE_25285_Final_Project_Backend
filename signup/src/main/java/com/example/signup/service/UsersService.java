package com.example.signup.service;

import com.example.signup.reset.InvalidTokenException;
import com.example.signup.modal.UsersModel;
import com.example.signup.repository.ResetToken;
import com.example.signup.repository.ResetTokenRepository;
import com.example.signup.repository.UsersRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.util.*;

@Service
@Slf4j
@Transactional(readOnly = true)
public class UsersService implements UserDetailsService {

    @Autowired
    private UsersRepository userRepository;

    @Autowired
    private ResetTokenRepository resetTokenRepository;

    @Autowired
    private JavaMailSender mailSender;

    private final PasswordEncoder passwordEncoder;
//    private final EmailService emailService;

    private static final long RESET_TOKEN_EXPIRATION_HOURS = 24;

    @Autowired
    public UsersService(UsersRepository userRepository, PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
//        this.emailService=emailService;
    }

    public UsersModel authenticate(String login, String password) {
        // Step 1: Fetch user by login, which returns an Optional
        Optional<UsersModel> optionalUser = userRepository.findByLogin(login);

        // Step 2: Check if user exists, then validate the password
        if (optionalUser.isPresent()) {
            UsersModel user = optionalUser.get(); // Get the actual UsersModel object from the Optional
            // Step 3: If the password matches, return the authenticated user
            if (passwordEncoder.matches(password, user.getPassword())) {
                return user;
            }
        }

        // Return null if authentication fails (either user not found or password mismatch)
        return null;
    }

    @Override
    @Transactional(readOnly = true)
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        // Fetch user from the database using login
        Optional<UsersModel> optionalUser = userRepository.findByLogin(username);

        // Handle case when the user is not found
        UsersModel user = optionalUser.orElseThrow(() -> new UsernameNotFoundException("User not found"));

        // Prepend "ROLE_" to the user's role to match Spring Security's expectations
        String roleWithPrefix = "ROLE_" + user.getRole();  // e.g., "ADMIN" becomes "ROLE_ADMIN"

        // Return a UserDetails object with the user's login, password, and authorities (roles)
        return new org.springframework.security.core.userdetails.User(
                user.getLogin(),
                user.getPassword(),
                Collections.singleton(new SimpleGrantedAuthority(roleWithPrefix))
        );
    }



    @Transactional(readOnly = false)
    public UsersModel registerUser(String login, String password, String email, String role) {
        if (userRepository.findByLogin(login).isPresent()) {
            return null; // User already exists
        }

        UsersModel user = new UsersModel();
        user.setLogin(login);
        user.setPassword(getPasswordEncoder().encode(password));
        user.setEmail(email);
        user.setRole(role);

        return userRepository.save(user);
    }

    @Autowired
    private ObjectProvider<PasswordEncoder> passwordEncoderProvider;

    private PasswordEncoder getPasswordEncoder() {
        return passwordEncoderProvider.getIfAvailable(() -> new BCryptPasswordEncoder());
    }


    public List<UsersModel> getAllUsers() {
        return userRepository.findAll();
    }

    public String getLoggedInUserLogin() {
        return SecurityContextHolder.getContext().getAuthentication().getName();
    }


//    public void initiatePasswordReset(String email) {
//        Optional<UsersModel> userOpt = usersRepository.findByEmail(email);
//        if (userOpt.isPresent()) {
//            UsersModel user = userOpt.get();
//            String token = generateResetToken();
//            user.setResetToken(token);
//            user.setTokenExpiry(LocalDateTime.now().plusHours(RESET_TOKEN_EXPIRATION_HOURS));
//            usersRepository.save(user);
//
//            emailService.sendPasswordResetEmail(email, token);
//        }
//        // Don't throw exception if email not found (security best practice)
//    }


    public boolean validateResetToken(String token) {
        if (token == null || token.trim().isEmpty()) {
            return false;
        }

        Optional<UsersModel> userOpt = userRepository.findByResetToken(token);
        if (userOpt.isEmpty()) {
            return false;
        }

        UsersModel user = userOpt.get();
        return user.getTokenExpiry() != null &&
                LocalDateTime.now().isBefore(user.getTokenExpiry());
    }


    @Transactional(readOnly = false)
    public void resetPassword(String token, String newPassword) {
        Optional<UsersModel> userOpt = userRepository.findByResetToken(token);
        if (userOpt.isEmpty() || !validateResetToken(token)) {
            throw new InvalidTokenException("Invalid or expired reset token");
        }

        UsersModel user = userOpt.get();
        user.setPassword(passwordEncoder.encode(newPassword));
        user.setResetToken(null);
        user.setTokenExpiry(null);
        userRepository.save(user);
    }

    private String generateResetToken() {
        byte[] randomBytes = new byte[32];
        new SecureRandom().nextBytes(randomBytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(randomBytes);
    }






    @Transactional // Ensure transactional context
    public boolean sendPasswordResetEmail(String email) {
        Optional<UsersModel> user = userRepository.findByEmail(email);
        if (user == null) {
            return false; // User not found
        }

        // Delete any existing reset token for this user before generating a new one
        deleteExistingResetTokenByEmail(email);

        // Generate a new token and save it
        String token = UUID.randomUUID().toString();
        saveResetTokenForUser(user, token);

        // Prepare and send email
        String resetUrl = "http://localhost:8080/reset-password?token=" + token;
        String message = "To reset your password, click the link below:\n" + resetUrl;
        sendEmail(email, "Password Reset", message);

        return true;
    }



    @Transactional // Ensure transactional context
    public void saveResetTokenForUser(Optional<UsersModel> user, String token) {
        ResetToken resetToken = new ResetToken();
        resetToken.setToken(token);
        resetToken.setUser(user);
        resetToken.setExpiryDate(LocalDateTime.now().plusMinutes(15)); // Set token expiry to 15 minutes

        resetTokenRepository.save(resetToken);
    }


    @Transactional // Ensure transactional context
    public void deleteExistingResetTokenByEmail(String email) {
        Optional<UsersModel> user = userRepository.findByEmail(email);
        if (user != null) {
            resetTokenRepository.findByUser(user).ifPresent(resetToken -> {
                resetTokenRepository.delete(resetToken);
                System.out.println("Deleted existing token: " + resetToken.getToken());
            });
        }
    }


    private void sendEmail(String to, String subject, String body) {
        SimpleMailMessage message = new SimpleMailMessage();
        message.setTo(to);
        message.setSubject(subject);
        message.setText(body);
        mailSender.send(message);
    }

    public boolean doesEmailExist(String email) {
        return userRepository.findByEmail(email) != null;
    }


    public Optional<UsersModel> findUserByResetToken(String token) {
        return resetTokenRepository.findByToken(token)
                .map(ResetToken::getUser); // Directly map the ResetToken to User if present
    }

    public boolean validatePasswordResetToken(String token) {
        Optional<ResetToken> resetTokenOptional = resetTokenRepository.findByToken(token);
        if (resetTokenOptional.isPresent()) {
            ResetToken resetToken = resetTokenOptional.get();
            boolean isValid = resetToken.getExpiryDate().isAfter(LocalDateTime.now());
            System.out.println("Token: " + token + ", Valid: " + isValid); // Log the token status
            return isValid;
        }
        System.out.println("Token: " + token + " not found."); // Log if token is not found
        return false;
    }


    @Transactional(readOnly = false)
    public boolean resetUserPassword(String token, String newPassword) {
        // Validate the token
        if (!validatePasswordResetToken(token)) {
            System.out.println("Invalid or expired token: " + token);
            return false; // Token is invalid or expired
        }

        // Find the user associated with the token
        Optional<UsersModel> userOptional = findUserByResetToken(token);
        if (!userOptional.isPresent()) {
            System.out.println("No user found for the token: " + token);
            return false;
        }

        UsersModel user = userOptional.get();
        user.setPassword(newPassword); // Update the user's password
        userRepository.save(user);

        // Invalidate the token after successful password reset
        resetTokenRepository.deleteByToken(token);

        return true;
    }
}



//@Service
//public class UsersService implements UserDetailsService {
//
//    @Autowired
//    private UsersRepository usersRepository;
//
//    @Autowired
//    private PasswordEncoder passwordEncoder;
//
//    @Override
//    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
//        UsersModel user = usersRepository.findByLogin(username)
//                .orElseThrow(() -> new UsernameNotFoundException("User not found"));
//
//        return new org.springframework.security.core.userdetails.User(
//                user.getLogin(),
//                user.getPassword(),
//                Collections.singletonList(new SimpleGrantedAuthority(user.getRole()))
//        );
//    }
//
//    public UsersModel registerUser(String login, String password, String email, String role) {
//        if (usersRepository.findByLogin(login).isPresent()) {
//            return null; // User already exists
//        }
//
//        UsersModel user = new UsersModel();
//        user.setLogin(login);
//        user.setPassword(passwordEncoder.encode(password));
//        user.setEmail(email);
//        user.setRole(role);
//
//        return usersRepository.save(user);
//    }
//
//    // Remove the authenticate method as Spring Security will handle authentication
//}