package com.adamskas.security.refresh_token;

import com.adamskas.security.services.JwtService;
import com.adamskas.security.user.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.UUID;
import java.util.stream.Stream;

@Service
@RequiredArgsConstructor
public class RefreshTokenService {
    private final RefreshTokenRepository refreshTokenRepository;
    private final UserRepository userRepository;
    private final JwtService jwtService;

    @Value("${security.jwt.access-token.name}")
    private String accessTokenName;
    @Value("${security.jwt.refresh-token.name}")
    private String refreshTokenName;
    @Value("${security.jwt.access-token.presence.name}")
    private String accessTokenPresenceName;
    @Value("${security.jwt.refresh-token.presence.name}")
    private String refreshTokenPresenceName;
    @Value("${security.jwt.access-token.duration.time.ms}")
    protected long accessTokenDurationMs;
    @Value("${security.jwt.refresh-token.duration.time.ms}")
    private long refreshTokenDurationMs;

    public HttpHeaders refreshTokens(String token) {
        return refreshTokenRepository.findByToken(token)
                .map(this::verifyExpiration)
                .map(RefreshTokenEntity::getUsername)
                .map(String::toLowerCase)
                .map(userRepository::findByEmail)
                .orElseThrow(TokenRefreshException::new)
                .map(user -> {
                    String accessToken = jwtService.generateAccessToken(user);
                    String refreshToken = generateRefreshToken(user);

                    return createCookieHeaders(accessToken, refreshToken);

                })
                .orElseThrow(TokenRefreshException::new);
    }

    public String generateRefreshToken(UserDetails userDetails) {
        RefreshTokenEntity refreshToken = new RefreshTokenEntity();
        String username = userDetails.getUsername();

        refreshToken.setUsername(username);
        refreshToken.setExpiryDate(Instant.now().plusMillis(refreshTokenDurationMs));
        String token = UUID.randomUUID().toString();

        refreshToken.setToken(hashToken(token));

        refreshTokenRepository.save(refreshToken);
        return token;
    }

    private String hashToken(String token) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] messageDigest =
                    md.digest(token.getBytes(StandardCharsets.UTF_8));

            return convertToHex(messageDigest);
        } catch (NoSuchAlgorithmException e) {
            throw new TokenRefreshException();
        }
    }

    private String convertToHex(final byte[] messageDigest) {
        BigInteger bigint = new BigInteger(1, messageDigest);
        StringBuilder stringBuilder = new StringBuilder();
        stringBuilder.append(bigint.toString(16));
        if (stringBuilder.length() < 32) {
            stringBuilder.append("0".repeat(32 - stringBuilder.length()));
        }
        return stringBuilder.toString();
    }

    private RefreshTokenEntity verifyExpiration(RefreshTokenEntity token) throws TokenRefreshException {
        if (token.getExpiryDate().compareTo(Instant.now()) < 0) {
            refreshTokenRepository.delete(token);
            throw new TokenRefreshException();
        }

        return token;
    }

    private HttpHeaders createCookieHeaders(String accessToken, String refreshToken) {
        HttpHeaders headers = new HttpHeaders();

        Stream.of(
                String.format("%s=%s; Max-Age=%d; Path=/; HttpOnly; Secure", accessTokenName, accessToken, accessTokenDurationMs / 1000),
                String.format("%s=%s; Max-Age=%d; Path=/; HttpOnly; Secure", refreshTokenName, refreshToken, refreshTokenDurationMs / 1000),
                String.format("%s=; Max-Age=%d; Path=/; Secure;", accessTokenPresenceName, accessTokenDurationMs / 1000),
                String.format("%s=; Max-Age=%d; Path=/; Secure;", refreshTokenPresenceName, refreshTokenDurationMs / 1000)
        ).forEach(s -> headers.add("Set-Cookie", s));

        return headers;
    }

    public void deleteRefreshTokenByUsername(String username){
        refreshTokenRepository.deleteByUsername(username);
    }
}
