package com.example.signup.controller;

//import com.example.signup.languages.MyLocaleResolver;

import com.example.signup.audit.AuditLog;
import com.example.signup.audit.AuditLogRepository;
import com.example.signup.audit.AuditService;
import com.example.signup.modal.Movie;
import com.example.signup.modal.UsersModel;
import com.example.signup.service.MovieService;
import com.example.signup.service.UsersService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.MessageSource;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import java.security.Principal;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@CrossOrigin(origins = "http://localhost:5173")
@Controller
public class UsersController {

    private final UsersService usersService;
    private final MovieService movieService;
    private final AuditService auditService;
    private final AuditLogRepository auditLogRepository;
    private static final Logger log = LoggerFactory.getLogger(MovieController.class);

    @Autowired
    private MessageSource messageSource;

    @Autowired
    public UsersController(UsersService usersService, MovieService movieService, AuditService auditService, AuditLogRepository auditLogRepository) {
        this.usersService = usersService;
        this.movieService = movieService;
        this.auditService = auditService;
        this.auditLogRepository = auditLogRepository;


    }


    @GetMapping("/")
    public String getIndex() {
        return "index";
    }

    @GetMapping("/register")
    public String getRegisterPage(Model model) {
        model.addAttribute("registerRequest", new UsersModel());
        return "register_page";
    }


    @PostMapping("/register")
    public ResponseEntity<?> register(@RequestBody UsersModel usersModel) {
        try {
            UsersModel registeredUser = usersService.registerUser(
                    usersModel.getLogin(),
                    usersModel.getPassword(),
                    usersModel.getEmail(),
                    usersModel.getRole()
            );

            if (registeredUser == null) {
                return ResponseEntity
                        .badRequest()
                        .body(new ApiResponse(false, "Registration failed. Username may already exist."));
            }

            auditService.logAction("REGISTER", usersModel.getLogin(), "User registered successfully");

            return ResponseEntity
                    .ok()
                    .body(new ApiResponse(true, "Registration successful"));
        } catch (Exception e) {
            return ResponseEntity
                    .internalServerError()
                    .body(new ApiResponse(false, "An error occurred during registration: " + e.getMessage()));
        }
    }


    //    @GetMapping("/login")
//    public ResponseEntity<?> getLoginPage() {
//        return ResponseEntity.ok(new ApiResponse(true, "Login endpoint", null));
//    }
    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody UsersModel loginRequest) {
        try {
            // Authenticate user using login and password
            UsersModel authenticatedUser = usersService.authenticate(
                    loginRequest.getLogin(),
                    loginRequest.getPassword()
            );

            if (authenticatedUser == null) {
                return ResponseEntity
                        .badRequest()
                        .body(new ApiResponse(false, "Invalid login credentials"));
            }

            auditService.logAction("LOGIN", loginRequest.getLogin(), "User logged in successfully");

            return ResponseEntity
                    .ok()
                    .body(new ApiResponse(true, "Login successful", authenticatedUser));
        } catch (Exception e) {
            return ResponseEntity
                    .internalServerError()
                    .body(new ApiResponse(false, "An error occurred during login: " + e.getMessage()));
        }
    }


    @GetMapping("/admin_page")
//    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<?> getAdminPage(Principal principal) {
        try {
//            String username = principal.getName();
//            auditService.logAction("ACCESS_ADMIN_PAGE", username, "Admin accessed the admin page");

            Map<String, Object> adminData = new HashMap<>();
            adminData.put("userLogin", usersService.getLoggedInUserLogin());
            adminData.put("movies", movieService.getAllMovies());
            adminData.put("users", usersService.getAllUsers());
            adminData.put("auditLogs", auditLogRepository.findAll());

            return ResponseEntity.ok(new ApiResponse(true, "Admin data retrieved successfully", adminData));
        } catch (Exception e) {
            System.err.println(e);
            e.printStackTrace();
            return ResponseEntity.internalServerError()
                    .body(new ApiResponse(false, "Error retrieving admin data: " + e.getMessage()));
        }
    }


    @GetMapping("/personal_page")
    public ResponseEntity<?> getPersonalPage(Principal principal) {
        try {
            String username = (principal != null) ? principal.getName() : "Guest";
            Authentication auth = SecurityContextHolder.getContext().getAuthentication();

            auditService.logAction("ACCESS_PERSONAL_PAGE", username, username + " accessed their personal page");

            Map<String, Object> personalData = new HashMap<>();

            if (principal != null) {
                String userRole = auth.getAuthorities().stream()
                        .map(GrantedAuthority::getAuthority)
                        .collect(Collectors.joining(", "));
                personalData.put("userLogin", username);
                personalData.put("userRole", userRole);
            } else {
                personalData.put("userLogin", "Guest");
                personalData.put("userRole", "GUEST");
            }

            personalData.put("movies", movieService.getAllMovies());
            personalData.put("recommendedMovies", movieService.getRecommendedMovies());

            return ResponseEntity.ok(new ApiResponse(true, "Personal page data retrieved successfully", personalData));
        } catch (Exception e) {
            return ResponseEntity.internalServerError()
                    .body(new ApiResponse(false, "Error retrieving personal page data: " + e.getMessage()));
        }
    }


    @GetMapping("/forgot-password")
    public String forgotPasswordRedirect() {
        // Redirect to PasswordResetController's method
        return "redirect:/password-reset/forgot-password";
    }


    @PostMapping("/admin_page")
//    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<?> createMovie(
            @RequestParam String name,
            @RequestParam String description,
            @RequestParam("imageFile") MultipartFile imageFile) {
        try {
            String imageUrl = movieService.saveImage(imageFile);
            Movie movie = movieService.createMovie(name, description, imageUrl);

            String successMessage = messageSource.getMessage(
                    "movie.success.creation", null, LocaleContextHolder.getLocale());

            return ResponseEntity.ok(new ApiResponse(true, successMessage, movie));
        } catch (Exception e) {
            log.error("Error creating movie: ", e);
            String errorMessage = messageSource.getMessage(
                    "movie.error.creation", null, LocaleContextHolder.getLocale());

            return ResponseEntity.internalServerError()
                    .body(new ApiResponse(false, errorMessage + ": " + e.getMessage()));
        }
    }

}
