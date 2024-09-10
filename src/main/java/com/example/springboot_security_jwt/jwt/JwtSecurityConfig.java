package com.example.springboot_security_jwt.jwt;

import lombok.AllArgsConstructor;
import org.springframework.security.config.annotation.SecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

// SecurityConfigurerAdapter는 Spring Security에서 보안 설정을 위한 클래스이다.
@AllArgsConstructor
public class JwtSecurityConfig extends SecurityConfigurerAdapter<DefaultSecurityFilterChain, HttpSecurity> {
    private final TokenProvider tokenProvider;

    // SecurityConfigurerAdapter 클래스의 configure 메서드를 오버라이드하고 있다.
    // 이 메서드는 Spring Security의 필터 체인을 설정하는 역할을 한다.
    // HttpSecurity 객체는 Spring Security의 보안 설정을 구성하는 핵심 클래스이다.
    // 이 객체는 HTTP 요청에 대한 보언 설정을 다루며, 여기서 필터 체인을 구성한다.
   @Override
   public void configure(HttpSecurity http) {

       // HttpSecurity 객체에 JwtFilter를 추가한다. addFilterBefore 메서드는 지정한 필터를 다른 필터 앞에 배치한다.
       // JwtFilter는 UsernamePasswordAuthenticationFilter 보다 먼저 실행된다.
       // 즉, 요청이 UsernamePasswordAuthenticationFilter에 도달하기 전에 JwtFilter가 JWT를 확인하고 인증을 처리한다.
       http.addFilterBefore(
           new JwtFilter(tokenProvider),
           UsernamePasswordAuthenticationFilter.class
       );
   }
}

// 이 클래스는 Spring Security의 필터 체인에 JwtFilter를 추가하는 구성 요소이다.
// TokenProvider를 통해 JWT 인증을 처리하는 JwtFilter를 생성하고,
// 이를 UsernamePasswordAuthenticationFilter 앞에 배치하여 JWT 기반 인증이 먼저 처리되도록 설정한다.
// Spring Security가 HTTP 요청을 처리할 때 이 필터가 먼저 실행되어 JWT를 확인하고
// 해당 토큰이 유효하다면 Spring Security 컨텍스트에 인증 정보를 저장한다.