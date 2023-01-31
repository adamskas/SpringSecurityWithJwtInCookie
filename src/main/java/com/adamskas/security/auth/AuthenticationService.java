package com.adamskas.security.auth;

import com.adamskas.security.services.JwtService;
import com.adamskas.security.user.Role;
import com.adamskas.security.user.UserEntity;
import com.adamskas.security.user.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthenticationService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;

    public AuthenticationResponse register(RegisterRequest request) {
        UserEntity userToBeRegistered = UserEntity.builder()
                .firstname(request.getFirstname())
                .lastname(request.getLastname())
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .role(Role.USER)
                .build();
        UserEntity savedUser = userRepository.save(userToBeRegistered);
        String jwtToken = jwtService.generateToken(savedUser);
        return AuthenticationResponse
                .builder()
                .token(jwtToken)
                .build();
    }

    public AuthenticationResponse authenticate(AuthenticationRequest request) {
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.getEmail(),
                        request.getPassword())
        );

        UserEntity loggedUser = userRepository
                .findByEmail(request.getEmail())
                .orElseThrow(); //TODO: create exception when user not found

        String jwtToken = jwtService.generateToken(loggedUser);
        return AuthenticationResponse
                .builder()
                .token(jwtToken)
                .build();
    }
}
