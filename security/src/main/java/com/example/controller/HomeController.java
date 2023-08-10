package com.example.controller;

import com.example.dto.CredentialsDTO;
import com.example.dto.RegisterDTO;
import com.example.security.TokenProvider;
import com.example.service.UserService;
import jakarta.annotation.security.RolesAllowed;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@CrossOrigin
public class HomeController {

    private final UserService userService;
    private final TokenProvider tokenProvider;

    @Autowired
    public HomeController(UserService userService, TokenProvider tokenProvider) {
        this.userService = userService;
        this.tokenProvider = tokenProvider;
    }

    @GetMapping("/")
    public ResponseEntity<String> homeController() {
        return ResponseEntity.ok("Daaa");
    }

    @PostMapping("/login")
    public ResponseEntity<String> loginController(@RequestBody CredentialsDTO credentialsDTO) {
        try {
            String token = userService.authenticate(credentialsDTO);

            return ResponseEntity.ok(token);
        } catch (Exception runtimeException) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Invalid credentials");

        }
    }

    @PostMapping("/register")
    public ResponseEntity<String> loginController(@RequestBody RegisterDTO registerDTO) {
        try {
            userService.registerUser(registerDTO);
            return ResponseEntity.ok("User registered");
        } catch (RuntimeException e) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("User registered");
        }
    }

    @GetMapping("/admin")
    public ResponseEntity<String> admin() {
        return ResponseEntity.ok("Da, esti admin");
    }

    @GetMapping("/user")
    public ResponseEntity<String> user() {
        return ResponseEntity.ok("Da, esti user");
    }

    @GetMapping("/oricare")
    public ResponseEntity<String> oricare() {
        return ResponseEntity.ok("Da, esti oricare");
    }
}
