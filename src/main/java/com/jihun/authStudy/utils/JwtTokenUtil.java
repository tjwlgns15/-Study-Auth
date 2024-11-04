package com.jihun.authStudy.utils;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import javax.crypto.SecretKey;
import java.util.Date;
import java.nio.charset.StandardCharsets;

public class JwtTokenUtil {
    // jwt 발급
    public static String createToken(String username, String key, long expireTimeMs) {
        // SecretKey 생성
        SecretKey secretKey = Keys.hmacShaKeyFor(key.getBytes(StandardCharsets.UTF_8));

        return Jwts.builder()
                .claim("username", username)
                .issuedAt(new Date(System.currentTimeMillis()))
                .expiration(new Date(System.currentTimeMillis() + expireTimeMs))
                .signWith(secretKey)
                .compact();
    }

    // SecretKey를 사용해 토큰 파싱
    private static Claims extractClaims(String token, String key) {
        SecretKey secretKey = Keys.hmacShaKeyFor(key.getBytes(StandardCharsets.UTF_8));

        return Jwts.parser()
                .verifyWith(secretKey)
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    // 토큰에서 secretKey 사용해 username 확인
    public static String getUsername(String token, String secretKey) {
        return extractClaims(token, secretKey).get("username").toString();
    }

    // jwt의 만료 시간 체크
    public static boolean isExpired(String token, String secretKey) {
        return extractClaims(token, secretKey).getExpiration().before(new Date());
    }
}