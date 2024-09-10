package com.example.springboot_security_jwt.controller;

import com.example.springboot_security_jwt.dto.MemberDto;
import com.example.springboot_security_jwt.service.MemberService;
import jakarta.validation.Valid;
import lombok.AllArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

@RestController
@AllArgsConstructor
@RequestMapping("/api")
public class UserController {
    private final MemberService memberService;

    @PostMapping("/signup")
    public ResponseEntity<MemberDto> signup(@Valid @RequestBody MemberDto memberDto) {
        return ResponseEntity.ok(memberService.signup(memberDto));
    }

    @GetMapping("/user")
    // user, admin 권한이 있는 사용자만 이 API에 접근할 수 있다.
    @PreAuthorize("hasAnyRole('USER','ADMIN')")
    public ResponseEntity<MemberDto> getMyUserInfo() {
        return ResponseEntity.ok(memberService.getMyUserWithAuthorities());
    }

    @GetMapping("/user/{username}")
    // admin 권한이 있는 사용자만 이 API에 접근할 수 있다.
    @PreAuthorize("hasAnyRole('ADMIN')")
    public ResponseEntity<MemberDto> getUserInfo(@PathVariable String username) {
        return ResponseEntity.ok(memberService.getUserWithAuthorities(username));
    }
}
