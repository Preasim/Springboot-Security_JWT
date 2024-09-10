package com.example.springboot_security_jwt.controller;

import com.example.springboot_security_jwt.dto.LoginDto;
import com.example.springboot_security_jwt.dto.TokenDto;
import com.example.springboot_security_jwt.jwt.JwtFilter;
import com.example.springboot_security_jwt.jwt.TokenProvider;
import jakarta.validation.Valid;
import lombok.AllArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@AllArgsConstructor
@RequestMapping("/api")
public class AuthController {
    private final TokenProvider tokenProvider;
    // Spring Security에서 인증을 처리하는 데 필요한 AuthenticationManager를 빌드하는 도구이다.
    private final AuthenticationManagerBuilder authenticationManagerBuilder;

    @PostMapping("/authenticate")
    public ResponseEntity<TokenDto> authorize(@Valid @RequestBody LoginDto loginDto) {
        // 사용자의 자격 증명을 담는 객체이다. 인증 과정에 사용된다.
        UsernamePasswordAuthenticationToken authenticationToken =
            new UsernamePasswordAuthenticationToken(loginDto.getUsername(), loginDto.getPassword());

        // authenticationManagerBuilder에서 AuthenticationManager 객체를 빌드하여 인증을 수행한다.
        // 인증이 성공하면 Authentication 객체가 반환된다.
        // authentication 토큰을 이용해서 authenticate 메소드가 실행이 될때 CustomUserDetailsService의 loadUserByUsername 메소드가 실행이 된다.
        // 실행이 된 후 authentication 객체를 생성하게 된다.
        Authentication authentication = authenticationManagerBuilder.getObject().authenticate(authenticationToken);

        // Spring Security에서 현재 인증된 사용자의 정보를 저장하고 관리하는 역할을 한다.
        // 여기에 인증이 완료된 Authentication 객체를 설정하여 해당 사용자가 인증되었음을 저장한다.
        SecurityContextHolder.getContext().setAuthentication(authentication);

        // 인증된 사용자의 정보를 기반으로 JWT 토큰을 생성한다.
        String jwt = tokenProvider.createToken(authentication);

        // HTTP 응답 헤더를 생성하고 응답 헤더에 Authorization 필드를 추가한다.
        // 그 값으로 Bearer 타입의 JWT 토큰을 추가한다.
        // 이로 인해 클라이언트가 응답을 받을 때, 헤더에서 JWT 토큰을 확인할 수 있다.
        HttpHeaders httpHeaders = new HttpHeaders();
        httpHeaders.add(JwtFilter.AUTHORIZATION_HEADER, "Bearer " + jwt);

        // TokenDto 객체에 JWT 토큰을 담아 응답 본문으로 반환한다.
        return new ResponseEntity<>(new TokenDto(jwt), httpHeaders, HttpStatus.OK);
    }
}

// 클라이언트가 /api/authenticate 경로로 로그인 요청을 보내면, 사용자 자격 증명을 확인하고,
// 성공 시 JWT 토큰을 생성하여 반환하는 역할을 한다.
// JWT는 헤더와 응답 본문에 포함되며, 이후 클라이언트는 이 토큰을 인증된 요청에 사용할 수 있다.