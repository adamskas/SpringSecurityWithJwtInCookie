package com.adamskas.security.auth;

import com.adamskas.security.exceptions.TokenRefreshException;
import com.adamskas.security.exceptions.UserWithEmailAlreadyExists;
import com.adamskas.security.refresh_token.RefreshTokenService;
import com.adamskas.security.services.JwtService;
import com.adamskas.security.user.Role;
import com.adamskas.security.user.UserEntity;
import com.adamskas.security.user.UserRepository;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Arrays;
import java.util.Optional;
import java.util.stream.Stream;


@Service
@RequiredArgsConstructor
public class AuthenticationService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;
    private final RefreshTokenService refreshTokenService;
    private final UserDetailsService userDetailsService;

    @Value("${security.jwt.refresh-token.duration.time.ms}")
    private long refreshTokenDurationMs;

    @Value("${security.jwt.access-token.duration.time.ms}")
    protected long accessTokenDurationMs;

    @Value("${security.jwt.access-token.name}")
    private String accessTokenName;
    @Value("${security.jwt.refresh-token.name}")
    private String refreshTokenName;
    @Value("${security.jwt.access-token.presence.name}")
    private String accessTokenPresenceName;
    @Value("${security.jwt.refresh-token.presence.name}")
    private String refreshTokenPresenceName;

    public HttpHeaders register(RegisterRequest request) {
        UserEntity userToBeRegistered = UserEntity.builder()
                .firstname(request.getFirstname())
                .lastname(request.getLastname())
                .email(request.getEmail().toLowerCase())
                .password(passwordEncoder.encode(request.getPassword()))
                .role(Role.USER)
                .build();

        if(userRepository.findByEmail(request.getEmail().toLowerCase()).isPresent()){
            throw new UserWithEmailAlreadyExists();
        }

        UserEntity savedUser = userRepository.save(userToBeRegistered);

        String accessToken = jwtService.generateAccessToken(savedUser);
        String refreshToken = refreshTokenService.generateRefreshToken(savedUser);

        return createCookieHeaders(accessToken, refreshToken);
    }

    public HttpHeaders authenticate(AuthenticationRequest request) {
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.getEmail().toLowerCase(),
                        request.getPassword())
        );

        UserEntity loggedUser = userRepository
                .findByEmail(request.getEmail().toLowerCase())
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));

        String accessToken = jwtService.generateAccessToken(loggedUser);
        String refreshToken = refreshTokenService.generateRefreshToken(loggedUser);

        return createCookieHeaders(accessToken, refreshToken);
    }

    public HttpHeaders refresh(HttpServletRequest request) {
        Cookie[] cookies = request.getCookies();
        if(cookies == null || cookies.length == 0){
            throw new TokenRefreshException();
        }

        Cookie requestRefreshToken = Arrays.stream(cookies)
                .filter(cookie -> cookie.getName().equals(refreshTokenName))
                .findAny()
                .orElseThrow(TokenRefreshException::new);

        return refreshTokenService.refreshTokens(requestRefreshToken.getValue());
    }

    public HttpHeaders logout( HttpServletRequest request) {
        //clearing cookies
        HttpHeaders logoutCookieHeaders = createLogoutCookieHeaders();

        //clear saved refresh_token from access_token credentials
        if (request.getCookies() == null || request.getCookies().length == 0) {
            return logoutCookieHeaders;
        }

        Optional<Cookie> accessCookie = Arrays.stream(request.getCookies())
                .filter(cookie -> cookie.getName().equals(accessTokenName))
                .findAny();

        if (accessCookie.isEmpty()) {
            return logoutCookieHeaders;
        }

        String accessToken = accessCookie.get().getValue();
        String userEmail = jwtService.extractUsername(accessToken);

        UserDetails userDetails = userDetailsService.loadUserByUsername(userEmail);

        if (!jwtService.isTokenValid(accessToken, userDetails)) {
            return logoutCookieHeaders;
        }

        refreshTokenService.deleteRefreshTokenByUsername(userEmail);
        return logoutCookieHeaders;
    }

    private HttpHeaders createCookieHeaders(String accessToken, String refreshToken, long accessTokenDuration, long refreshTokenDuration) {
        HttpHeaders headers = new HttpHeaders();

        Stream.of(
                String.format("%s=%s; Max-Age=%d; Path=/; HttpOnly; Secure", accessTokenName, accessToken, accessTokenDuration),
                String.format("%s=%s; Max-Age=%d; Path=/; HttpOnly; Secure", refreshTokenName, refreshToken, refreshTokenDuration),
                String.format("%s=; Max-Age=%d; Path=/; Secure;", accessTokenPresenceName, accessTokenDuration),
                String.format("%s=; Max-Age=%d; Path=/; Secure;", refreshTokenPresenceName, refreshTokenDuration)
        ).forEach(s -> headers.add("Set-Cookie", s));

        return headers;
    }

    private HttpHeaders createLogoutCookieHeaders() {
        return createCookieHeaders(null, null, 0, 0);
    }

    private HttpHeaders createCookieHeaders(String accessToken, String refreshToken) {
        return createCookieHeaders(accessToken, refreshToken, accessTokenDurationMs / 1000, refreshTokenDurationMs / 1000);
    }
}
