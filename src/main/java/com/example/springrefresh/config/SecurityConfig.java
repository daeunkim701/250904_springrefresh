package com.example.springrefresh.config;

import com.example.springrefresh.filter.JwtFilter;
import com.example.springrefresh.util.JwtUtil;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.List;

// @ -> annotation
// 1. 설정
// 2. WebSecurity
// 3. 의존성 주입
@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {
    private final JwtUtil jwtUtil;
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        // CORS 설정
        http.cors(cors -> cors.configurationSource(corsConfigurationSource()));

        // CSRF 비활성화 (JWT 사용 시 불필요)
        http.csrf(AbstractHttpConfigurer::disable);

        // Form 로그인 방식 비활성화
        http.formLogin(AbstractHttpConfigurer::disable);

        // HTTP Basic 인증 방식 비활성화
        http.httpBasic(AbstractHttpConfigurer::disable);

        // 세션 관리: STATELESS (JWT 사용 시 세션을 사용하지 않음)
        http.sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));

        // 경로별 인가 작업
        http.authorizeHttpRequests(auth -> auth
                .requestMatchers("/", "/login", "/reissue").permitAll() // 해당 경로는 모두 허용
                .requestMatchers("/api/**").hasRole("USER") // /api/** 경로는 USER 역할 필요
                .anyRequest().authenticated() // 나머지 요청은 인증 필요
        );

        // 커스텀 JWT 필터 추가 (UsernamePasswordAuthenticationFilter 이전에 실행)
        http.addFilterBefore(new JwtFilter(jwtUtil), UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    // 개발 환경용 CORS 설정 (프론트엔드 127.0.0.1:5500 허용)
    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration config = new CorsConfiguration();
//        config
        config.setAllowedOrigins(List.of("http://127.0.0.1:5500"));
        // VSCode Live Server
        config.setAllowedMethods(List.of("*")); // POST, GET
        config.setAllowedHeaders(List.of("*")); // Content-Type, Authorization
        config.setAllowCredentials(true);
        config.setMaxAge(3600L);
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", config);
        return source;
    }

    // 1. 비밀번호 암호화 Bean
    @Bean
    public PasswordEncoder passwordEncoder() { // 로그인 시도나 가입할 때 암호화
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

    // 2. AuthenticationManager Bean (로그인 시 사용)
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception {
        return configuration.getAuthenticationManager();
    }

    // 3. 테스트용 인메모리 사용자 설정
    @Bean
    public UserDetailsService userDetailsService() {
        UserDetails user = User.builder()
                .username("user") // id: user
                .password(passwordEncoder().encode("1234")) // pw: 1234
                .roles("USER")
                .build();
        return new InMemoryUserDetailsManager(user);
    }
}
