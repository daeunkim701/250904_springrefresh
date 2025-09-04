package com.example.springrefresh.filter;

import com.example.springrefresh.util.JwtUtil;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;

@RequiredArgsConstructor
public class JwtFilter extends OncePerRequestFilter {

    private final JwtUtil jwtUtil;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        // 1. Authorization 헤더에서 토큰 추출
        String authorization = request.getHeader("Authorization");
        // 토큰 이름이 다를 수도 있다!!

        // 2. 토큰 존재 여부 확인, 토큰이 없거나, 'Bearer '로 시작하지 않으면 다음 필터로
        if (authorization == null || !authorization.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return;
        }

        // 3. 'Bearer ' 부분 제거 (스킴을 체크)
        // String accessToken = authorization.substring(7); // 7자리 명시
        String accessToken = authorization.substring("Bearer ".length()); // 7자리 명시

        // 4. 토큰 만료 여부 확인 (만료 시 다음 필터로)
        if (jwtUtil.isExpired(accessToken)) {
            filterChain.doFilter(request, response);
            return;
        }

        // 5. 토큰에서 username, role 추출 (정보들 추출)
        String username = jwtUtil.getUsername(accessToken);
        String role = jwtUtil.getRole(accessToken);

        // 6. UserDetails 객체 생성 (여기서는 간단히 생성)
        User user = new User(username, "", List.of(new SimpleGrantedAuthority("ROLE_" + role)));

        // 7. SecurityContext에 인증 정보 설정
        Authentication authToken = new UsernamePasswordAuthenticationToken(user, null, user.getAuthorities());
        SecurityContextHolder.getContext().setAuthentication(authToken);

        // 다음 필터 실행, 다음 필터로 넘기겠다는 것
        filterChain.doFilter(request, response);
    }
}