package com.example.springrefresh;

import org.springframework.stereotype.Repository;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

@Repository // JPARepository가 @NoBeanRepository를 가지고 있음 그래서 스캔이 돼
public class RefreshTokenRepository {
    private final Map<String, String> refreshTokens = new ConcurrentHashMap<>();

    public void save(String username, String refreshToken) {
        refreshTokens.put(username, refreshToken); // 중복 로그인을 막는 효과
    }

    public Optional<String> findByUsername(String username) {
        return Optional.ofNullable(refreshTokens.get(username));
        // 값이 null이 아니면 String이고 값이 null이면 empty
    }

}
