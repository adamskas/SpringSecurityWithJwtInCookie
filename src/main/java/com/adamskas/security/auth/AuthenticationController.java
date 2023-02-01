package com.adamskas.security.auth;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Null;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthenticationController {

    private final AuthenticationService authenticationService;

    @PostMapping("/register")
    public ResponseEntity<Null> register(
            @RequestBody @Valid RegisterRequest request) {
        return ResponseEntity.status(HttpStatus.OK)
                .headers(authenticationService.register(request))
                .build();
    }

    @PostMapping("/authenticate")
    public ResponseEntity<Null> authenticate(
            @RequestBody @Valid AuthenticationRequest request) {
        return ResponseEntity.status(HttpStatus.OK)
                .headers(authenticationService.authenticate(request)).build();
    }

    @PostMapping("/refresh")
    public ResponseEntity<Null> refresh(
            HttpServletRequest request) {
        return ResponseEntity
                .status(HttpStatus.OK)
                .headers(authenticationService.refresh(request))
                .build();
    }

    @PostMapping("/logout")
    public ResponseEntity<Null> logout(
            HttpServletRequest request) {
        return ResponseEntity
                .status(HttpStatus.OK)
                .headers(authenticationService.logout(request))
                .build();
    }
}
