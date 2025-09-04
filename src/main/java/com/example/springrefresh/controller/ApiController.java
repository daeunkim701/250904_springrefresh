package com.example.springrefresh.controller;

import org.apache.catalina.User;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

// controller/ApiController.java
@RestController
public class ApiController {
    @GetMapping("/api/hello")
    public ResponseEntity<String> hello(@AuthenticationPrincipal User user) {
        // SecurityContext에서 인증된 사용자 정보 가져오기
        return ResponseEntity.ok("Hello " + user.getUsername() + ", 당신은 user입니다.");
    }
}
