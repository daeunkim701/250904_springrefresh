package com.example.springrefresh.util;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Date;

@Component // 의존성 주입을 편하게 하기 위해 -> 컨테이너 등록
public class JwtUtil {
    // @Value 때문에 직접 생성자를 작성하거나 필드 주입
    private final SecretKey secretKey;
    private final Long accessExpirationMs; // accessToken의 만료일
    private final Long refreshExpirationMs; // refreshToken의 만료일

    // 자동으로 생성이 되어서 컨테이너에 등록
    public JwtUtil (
            // {jwt.secret} -> application.yml과 호응되어야 함
            @Value("${jwt.secret}") String secret,
            @Value("${jwt.access-token-expiration}") Long accessExpirationMs,
            @Value("${jwt.refresh-token-expiration}") Long refreshExpirationMs
    ) {
        // 비밀 키를 Base64 디코딩하여 SecretKey 객체로 변환
        // this.secretKey = new SecretKeySpec(Decoders.BASE64.decode(secret), Jwts.SIG.HS256.key().build().getAlgorithm());
        // soutv 하면 자동완성
        System.out.println("secret = " + secret);
        System.out.println("accessExpirationMs = " + accessExpirationMs);
        System.out.println("refreshExpirationMs = " + refreshExpirationMs);
        this.secretKey = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8)); // 텍스트 -> 바이트 => 암호화된 인코딩으로 바꿔서 JWT에 쓸 수 있게 하겠다
        this.accessExpirationMs = accessExpirationMs;
        this.refreshExpirationMs = refreshExpirationMs;
    }

    // 사용자 이름과 역할을 기반으로 JWT 토큰(액세스/리프레시) 생성
//    public String createAccessToken(String username, String role, String type) {
//        Date now = new Date();
//        Date expiration = new Date(now.getTime() + accessExpirationMs);
//        return Jwts.builder()
//                .subject(username) // 로그인 정보
//                .issuedAt(now)     // 발행일시
//                .expiration(expiration) // 만료일시
//                .signWith(secretKey) // 암호화
//                .compact();
//    }

    // 사용자 이름과 역할을 기반으로 JWT 토큰(액세스/리프레시) 생성
    public String createToken(String username, String role, String type) {
        Date now = new Date();
        // 만료일시가 분기가 되어야 한다
        Long expiration = type.equals("access") ? accessExpirationMs : refreshExpirationMs; // access -> 짧은 걸 주고, 아니면 긴 걸 준다
        Date expiryDate = new Date(now.getTime() + expiration);
        return Jwts.builder()
                .subject(username) // 로그인 정보
                // claim
                .claim("username", username)
                .claim("role", role)
                .issuedAt(now) // 발행일시
                .expiration(expiryDate) // 만료일시
                .signWith(secretKey) // 암호화
                .compact();
    }

}
